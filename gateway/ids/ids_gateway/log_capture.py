from __future__ import annotations

import json
import os
import time
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from .records import PacketRecord
from .utils import device_id_from_topic, safe_float


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


class SensorLogCapture:
    def __init__(self, file_path: str, use_mac: bool = False) -> None:
        self.file_path = Path(file_path)
        self.use_mac = use_mac
        self.buffer: Dict[str, List[PacketRecord]] = defaultdict(list)
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
            # First attach should tail new events only, not replay historical log lines.
            self._offset = current_size
            return

        if current_inode != self._inode or current_size < self._offset:
            # Log file rotated or truncated.
            self._inode = current_inode
            self._offset = 0

    def _record_from_obj(self, obj: Dict[str, Any]) -> Optional[PacketRecord]:
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
        event_ts_source = (
            "gateway_received_at"
            if gateway_received_at
            else "device_reported_at"
            if device_reported_at
            else "fallback_now"
        )

        test_phase = ""
        if isinstance(payload_obj, dict):
            test_phase = str(payload_obj.get("testPhase", "") or "")

        device_id = str(obj.get("deviceId", obj.get("username", "")) or "")
        if not device_id:
            device_id = device_id_from_topic(topic)

        pkt_len = len(json.dumps(payload_obj, ensure_ascii=False)) if payload_obj is not None else 0

        rec = PacketRecord(
            ts=float(ts),
            src_ip=src_ip,
            dst_ip=str(obj.get("gateway", "gateway") or "gateway"),
            src_port=int(obj.get("src_port", 0) or 0),
            dst_port=int(obj.get("dst_port", 1883) or 1883),
            proto=str(obj.get("proto", "TCP") or "TCP").upper(),
            pkt_len=int(pkt_len),
            tcp_flags=str(obj.get("tcp_flags", "") or "").upper(),
            observed_src_ip=src_ip,
            mqtt_topic=topic,
            mqtt_device_id=device_id,
            mqtt_payload=payload_obj,
            mqtt_delay=safe_float(obj.get("delay"), 0.0),
            gateway_received_at=gateway_received_at,
            device_reported_at=device_reported_at,
            test_phase=test_phase,
            capture_mode="sensor_log",
            semantic_quality="HIGH",
            event_ts_source=event_ts_source,
            extra={"log_source": str(self.file_path)},
        )
        return rec

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
                rec = self._record_from_obj(obj)
                if rec is None:
                    continue
                self.buffer[rec.src_ip].append(rec)
            self._offset = int(fh.tell())

    def sniff_once(self, timeout: int = 2) -> Dict[str, List[PacketRecord]]:
        timeout = max(int(timeout), 1)
        end = time.time() + timeout
        while time.time() < end:
            self._read_new_lines_once()
            time.sleep(0.05)

        data = dict(self.buffer)
        self.buffer.clear()
        return data
