from __future__ import annotations

import json
import logging
import time
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any

from .records import PacketRecord
from .utils import safe_float

logger = logging.getLogger(__name__)


def _parse_timestamp(value: Any) -> float | None:
    if not value:
        return None
    text = str(value).strip()
    try:
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        return datetime.fromisoformat(text).timestamp()
    except ValueError:
        return None


class StructuredEventCapture:
    """Tail the agent's accepted-message JSONL without losing partial writes."""

    def __init__(self, file_path: str | Path, *, start_at_end: bool = True) -> None:
        self.file_path = Path(file_path)
        self.start_at_end = start_at_end
        self.buffer: dict[str, list[PacketRecord]] = defaultdict(list)
        self._offset = 0
        self._inode: int | None = None
        self._initialized = False
        self._pending = b""

    def _record_from_obj(self, obj: dict[str, Any]) -> PacketRecord | None:
        if str(obj.get("event_type") or "").strip() != "sensor_data":
            return None
        device_id = str(obj.get("device_id") or "").strip()
        topic = str(obj.get("topic") or "").strip()
        if not device_id or not topic:
            return None
        payload = obj.get("payload")
        received_at = str(obj.get("gateway_received_at") or "")
        device_at = str(obj.get("device_reported_at") or "")
        timestamp = _parse_timestamp(received_at) or time.time()
        payload_size = int(safe_float(obj.get("payload_size_bytes"), 0.0))
        if payload_size <= 0 and payload is not None:
            payload_size = len(
                json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode(
                    "utf-8"
                )
            )
        return PacketRecord(
            ts=timestamp,
            src_ip="",
            dst_ip="gateway",
            src_port=0,
            dst_port=int(safe_float(obj.get("broker_port"), 0.0)),
            proto="TCP",
            pkt_len=payload_size,
            tcp_flags="",
            mqtt_topic=topic,
            mqtt_device_id=device_id,
            mqtt_payload=payload,
            mqtt_delay=safe_float(obj.get("delay"), 0.0),
            gateway_received_at=received_at,
            device_reported_at=device_at,
            capture_mode="sensor_log",
            semantic_quality="HIGH",
            event_ts_source="gateway_received_at",
            extra={
                "payload_size_bytes": payload_size,
                "event_type": "sensor_data",
            },
        )

    def _read_available(self) -> None:
        try:
            stat = self.file_path.stat()
        except FileNotFoundError:
            self._inode = None
            self._offset = 0
            self._pending = b""
            self._initialized = False
            return

        inode = int(stat.st_ino)
        if not self._initialized:
            self._inode = inode
            self._offset = stat.st_size if self.start_at_end else 0
            self._initialized = True
            if self.start_at_end:
                return
        elif inode != self._inode or stat.st_size < self._offset:
            self._inode = inode
            self._offset = 0
            self._pending = b""

        with self.file_path.open("rb") as handle:
            handle.seek(self._offset)
            chunk = handle.read()
            self._offset = handle.tell()
        if not chunk:
            return

        lines = (self._pending + chunk).split(b"\n")
        self._pending = lines.pop()
        for raw in lines:
            if not raw.strip():
                continue
            try:
                obj = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                logger.warning("ignoring malformed IDS event in %s: %s", self.file_path, exc)
                continue
            if not isinstance(obj, dict):
                logger.warning("ignoring non-object IDS event in %s", self.file_path)
                continue
            record = self._record_from_obj(obj)
            if record is not None:
                self.buffer[record.mqtt_device_id].append(record)

    def poll_once(self) -> dict[str, list[PacketRecord]]:
        self._read_available()
        records = dict(self.buffer)
        self.buffer.clear()
        return records
