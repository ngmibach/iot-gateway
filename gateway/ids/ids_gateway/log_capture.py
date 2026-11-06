from __future__ import annotations

import json
import re
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Deque, Dict, List, Optional, Tuple

from .records import PacketRecord
from .utils import device_id_from_topic, safe_float

_ACCEPTED_EVENT_TYPES = frozenset({"sensor_data"})

_MOSQUITTO_CONN_RE = re.compile(
    r"^(\d+): New client connected from ([\d.]+):\d+ as ([^\s(]+).*u'([^']+)'"
)
_MOSQUITTO_PUB_RE = re.compile(
    r"^(\d+): Received PUBLISH from ([^\s(]+).*'sensors/(sensor\d+)/process'"
)
_HAPROXY_SSL_FAIL_RE = re.compile(
    r"^(?P<ip>[\d.]+):.*SSL handshake failure"
)


def _parse_iso_ts(value: Any) -> Optional[float]:
    if not value:
        return None
    try:
        s = str(value).strip()
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        return datetime.fromisoformat(s).timestamp()
    except Exception:
        return None


@dataclass
class DeniedEventStats:
    total: int = 0
    by_type: Dict[str, int] = field(default_factory=dict)
    undersize_count: int = 0
    payload_sizes: List[int] = field(default_factory=list)


@dataclass
class MqttConnectStats:
    connect_count: int = 0
    publish_count: int = 0
    unique_ips: set[str] = field(default_factory=set)
    unique_client_ids: set[str] = field(default_factory=set)
    window_seconds: float = 0.0

    @property
    def connect_rate(self) -> float:
        if self.window_seconds <= 0:
            return 0.0
        return self.connect_count / self.window_seconds

    @property
    def connect_publish_ratio(self) -> float:
        if self.publish_count <= 0:
            return float(self.connect_count)
        return self.connect_count / self.publish_count


@dataclass
class HaproxySslStats:
    failure_count: int = 0
    window_seconds: float = 0.0


class SensorLogCapture:
    """Tail Node-RED sensor_data.log for accepted events and denied counters."""

    def __init__(self, file_path: str, use_mac: bool = False) -> None:
        self.file_path = Path(file_path)
        self.use_mac = use_mac
        self.buffer: Dict[str, List[PacketRecord]] = defaultdict(list)
        self.denied_counts: Dict[str, DeniedEventStats] = defaultdict(DeniedEventStats)
        self._offset = 0
        self._inode: Optional[int] = None

    def _refresh_file_state(self) -> None:
        if not self.file_path.exists():
            self._inode = None
            self._offset = 0
            return

        st = self.file_path.stat()
        current_inode = int(st.st_ino)
        current_size = int(st.st_size)

        if self._inode is None:
            self._inode = current_inode
            self._offset = current_size
            return

        if current_inode != self._inode or current_size < self._offset:
            self._inode = current_inode
            self._offset = 0

    def _track_denied(self, obj: Dict[str, Any], undersize_threshold: int = 2500) -> None:
        event_type = str(obj.get("event_type", "") or "").strip()
        if not event_type.startswith("denied"):
            return
        device_id = str(obj.get("deviceId", obj.get("username", "")) or "").strip()
        if not device_id:
            return
        denied_type = str(obj.get("denied_type", event_type) or event_type)
        stats = self.denied_counts[device_id]
        stats.total += 1
        stats.by_type[denied_type] = stats.by_type.get(denied_type, 0) + 1
        payload_size = int(safe_float(obj.get("payload_size_bytes", 0), 0.0))
        if payload_size > 0:
            stats.payload_sizes.append(payload_size)
            if payload_size < undersize_threshold:
                stats.undersize_count += 1

    def _record_from_obj(self, obj: Dict[str, Any]) -> Optional[PacketRecord]:
        event_type = str(obj.get("event_type", "") or "").strip()
        if event_type not in _ACCEPTED_EVENT_TYPES:
            return None

        src_ip = str(obj.get("source_ip", "") or "").strip()
        if not src_ip:
            return None

        topic = str(obj.get("topic", "") or "")
        payload_obj = obj.get("payload")
        if payload_obj is None:
            payload_obj = obj

        gateway_received_at = str(obj.get("gateway_received_at", "") or "")
        device_reported_at = str(obj.get("device_reported_at", "") or "")

        ts = (
            _parse_iso_ts(gateway_received_at)
            or _parse_iso_ts(device_reported_at)
            or time.time()
        )

        device_id = str(obj.get("deviceId", obj.get("username", "")) or "")
        if not device_id:
            device_id = device_id_from_topic(topic)
        if not device_id:
            return None

        payload_size = int(safe_float(obj.get("payload_size_bytes", 0), 0.0))
        if payload_size <= 0 and payload_obj is not None:
            try:
                payload_size = len(json.dumps(payload_obj, ensure_ascii=False))
            except Exception:
                payload_size = 0

        return PacketRecord(
            ts=float(ts),
            src_ip=src_ip,
            dst_ip=str(obj.get("gateway", "gateway") or "gateway"),
            src_port=0,
            dst_port=1883,
            proto="TCP",
            pkt_len=payload_size,
            tcp_flags="",
            observed_src_ip=src_ip,
            mqtt_topic=topic,
            mqtt_device_id=device_id,
            mqtt_payload=payload_obj,
            mqtt_delay=safe_float(obj.get("delay"), 0.0),
            gateway_received_at=gateway_received_at,
            device_reported_at=device_reported_at,
            capture_mode="sensor_log",
            semantic_quality="HIGH",
            event_ts_source="gateway_received_at",
            extra={
                "log_source": str(self.file_path),
                "payload_size_bytes": payload_size,
                "event_type": event_type,
            },
        )

    def _read_new_lines_once(self) -> None:
        self._refresh_file_state()
        if not self.file_path.exists():
            return

        with self.file_path.open("r", encoding="utf-8", errors="ignore") as fh:
            fh.seek(self._offset)
            for line in fh:
                raw = line.strip()
                if not raw:
                    continue
                try:
                    obj = json.loads(raw)
                except Exception:
                    continue
                if not isinstance(obj, dict):
                    continue
                self._track_denied(obj)
                rec = self._record_from_obj(obj)
                if rec is None:
                    continue
                device_key = rec.mqtt_device_id or rec.src_ip
                self.buffer[device_key].append(rec)
            self._offset = int(fh.tell())

    def poll_once(self) -> Dict[str, List[PacketRecord]]:
        self._read_new_lines_once()
        data = dict(self.buffer)
        self.buffer.clear()
        return data

    def sniff_once(self, timeout: float = 2) -> Dict[str, List[PacketRecord]]:
        timeout = max(float(timeout), 0.0)
        if timeout <= 0:
            return self.poll_once()

        end = time.time() + timeout
        while time.time() < end:
            self._read_new_lines_once()
            time.sleep(0.02)

        data = dict(self.buffer)
        self.buffer.clear()
        return data

    def consume_denied_counts(self) -> Dict[str, DeniedEventStats]:
        data = dict(self.denied_counts)
        self.denied_counts.clear()
        return data


class MosquittoLogCapture:
    """Tail Mosquitto broker log for MQTT connect/publish churn signals."""

    def __init__(self, file_path: str, window_seconds: int = 60) -> None:
        self.file_path = Path(file_path)
        self.window_seconds = max(int(window_seconds), 1)
        self._offset = 0
        self._inode: Optional[int] = None
        self._connect_events: Deque[Tuple[float, str, str, str]] = deque()
        self._publish_events: Deque[Tuple[float, str]] = deque()

    def _refresh_file_state(self) -> None:
        if not self.file_path.exists():
            self._inode = None
            self._offset = 0
            return

        st = self.file_path.stat()
        current_inode = int(st.st_ino)
        current_size = int(st.st_size)

        if self._inode is None:
            self._inode = current_inode
            self._offset = current_size
            return

        if current_inode != self._inode or current_size < self._offset:
            self._inode = current_inode
            self._offset = 0

    def _prune(self, now: float) -> None:
        cutoff = now - self.window_seconds
        while self._connect_events and self._connect_events[0][0] < cutoff:
            self._connect_events.popleft()
        while self._publish_events and self._publish_events[0][0] < cutoff:
            self._publish_events.popleft()

    def _read_new_lines_once(self) -> None:
        self._refresh_file_state()
        if not self.file_path.exists():
            return

        latest_ts = 0.0
        with self.file_path.open("r", encoding="utf-8", errors="ignore") as fh:
            fh.seek(self._offset)
            for line in fh:
                stripped = line.strip()
                conn_match = _MOSQUITTO_CONN_RE.search(stripped)
                if conn_match:
                    broker_ts, ip, client_id, username = conn_match.groups()
                    if username.startswith("sensor"):
                        ts = float(broker_ts)
                        self._connect_events.append((ts, username, ip, client_id))
                        latest_ts = max(latest_ts, ts)
                    continue
                pub_match = _MOSQUITTO_PUB_RE.search(stripped)
                if pub_match:
                    broker_ts, _client_id, username = pub_match.groups()
                    ts = float(broker_ts)
                    self._publish_events.append((ts, username))
                    latest_ts = max(latest_ts, ts)
            self._offset = int(fh.tell())

        if latest_ts > 0:
            self._prune(latest_ts)
        elif self._connect_events or self._publish_events:
            self._prune(time.time())

    def poll_once(self) -> Dict[str, MqttConnectStats]:
        self._read_new_lines_once()
        return self._build_stats()

    def _build_stats(self) -> Dict[str, MqttConnectStats]:
        stats: Dict[str, MqttConnectStats] = {}
        per_user_conn_ts: Dict[str, List[float]] = defaultdict(list)

        for ts, username, ip, client_id in self._connect_events:
            entry = stats.setdefault(username, MqttConnectStats())
            entry.connect_count += 1
            entry.unique_ips.add(ip)
            entry.unique_client_ids.add(client_id)
            per_user_conn_ts[username].append(ts)

        for _ts, username in self._publish_events:
            entry = stats.setdefault(username, MqttConnectStats())
            entry.publish_count += 1

        for username, entry in stats.items():
            timestamps = sorted(per_user_conn_ts.get(username, []))
            if len(timestamps) >= 2:
                entry.window_seconds = max(timestamps[-1] - timestamps[0], 1.0)
            else:
                entry.window_seconds = float(self.window_seconds)
        return stats

    def sniff_once(self, timeout: float = 1) -> Dict[str, MqttConnectStats]:
        timeout = max(float(timeout), 0.0)
        if timeout <= 0:
            return self.poll_once()

        end = time.time() + timeout
        while time.time() < end:
            self._read_new_lines_once()
            time.sleep(0.02)
        return self._build_stats()


class HaproxyLogCapture:
    """Tail HAProxy log for TLS handshake failure spikes."""

    def __init__(self, file_path: str, window_seconds: int = 60) -> None:
        self.file_path = Path(file_path)
        self.window_seconds = max(int(window_seconds), 1)
        self._offset = 0
        self._inode: Optional[int] = None
        self._events: Deque[Tuple[float, str]] = deque()

    def _refresh_file_state(self) -> None:
        if not self.file_path.exists():
            self._inode = None
            self._offset = 0
            return

        st = self.file_path.stat()
        current_inode = int(st.st_ino)
        current_size = int(st.st_size)

        if self._inode is None:
            self._inode = current_inode
            self._offset = current_size
            return

        if current_inode != self._inode or current_size < self._offset:
            self._inode = current_inode
            self._offset = 0

    def _prune(self, now: float) -> None:
        cutoff = now - self.window_seconds
        while self._events and self._events[0][0] < cutoff:
            self._events.popleft()

    def _read_new_lines_once(self) -> None:
        self._refresh_file_state()
        if not self.file_path.exists():
            return

        now = time.time()
        with self.file_path.open("r", encoding="utf-8", errors="ignore") as fh:
            fh.seek(self._offset)
            for line in fh:
                match = _HAPROXY_SSL_FAIL_RE.search(line.strip())
                if match:
                    self._events.append((now, match.group("ip")))
            self._offset = int(fh.tell())
        self._prune(now)

    def poll_once(self) -> Dict[str, HaproxySslStats]:
        self._read_new_lines_once()
        return self._build_stats()

    def _build_stats(self) -> Dict[str, HaproxySslStats]:
        stats: Dict[str, HaproxySslStats] = {}
        for _ts, ip in self._events:
            entry = stats.setdefault(ip, HaproxySslStats())
            entry.failure_count += 1
            entry.window_seconds = float(self.window_seconds)
        return stats

    def sniff_once(self, timeout: float = 1) -> Dict[str, HaproxySslStats]:
        timeout = max(float(timeout), 0.0)
        if timeout <= 0:
            return self.poll_once()

        end = time.time() + timeout
        while time.time() < end:
            self._read_new_lines_once()
            time.sleep(0.02)
        return self._build_stats()