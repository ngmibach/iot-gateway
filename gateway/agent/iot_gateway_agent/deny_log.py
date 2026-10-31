"""Ring buffer + JSONL log of denied / invalid sensor messages."""

from __future__ import annotations

import json
import logging
import threading
import time
from collections import deque
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)

DEFAULT_MAX_EVENTS = 500


@dataclass
class DenyEvent:
    arrival_ms: int
    reason: str
    device_id: str
    source_ip: str = ""
    gateway_id: str = ""
    detail: str = ""

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


class DenyLog:
    """In-memory recent denies plus optional append-only JSONL on disk."""

    def __init__(
        self,
        *,
        path: Path | str | None = None,
        max_events: int = DEFAULT_MAX_EVENTS,
        gateway_id: str = "",
    ) -> None:
        self.path = Path(path) if path else None
        self.max_events = max(50, int(max_events))
        self.gateway_id = (gateway_id or "").strip()
        self._events: deque[DenyEvent] = deque(maxlen=self.max_events)
        self._lock = threading.Lock()
        self._ip_by_device: dict[str, str] = {}
        self._device_by_ip: dict[str, str] = {}
        self._ip_map_mtime: float = -1.0
        self._ip_map_path: Optional[Path] = None

    def set_gateway_id(self, gateway_id: str) -> None:
        self.gateway_id = (gateway_id or "").strip()

    def set_ip_map_path(self, path: Path | str | None) -> None:
        self._ip_map_path = Path(path) if path else None
        self._ip_map_mtime = -1.0

    def _refresh_ip_map(self) -> None:
        path = self._ip_map_path
        if path is None or not path.is_file():
            return
        try:
            mtime = path.stat().st_mtime
        except OSError:
            return
        if mtime == self._ip_map_mtime:
            return
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            logger.debug("deny_log ip-map read failed: %s", exc)
            return
        devices = raw.get("devices") if isinstance(raw, dict) else None
        if not isinstance(devices, dict):
            return
        ip_by_device: dict[str, str] = {}
        device_by_ip: dict[str, str] = {}
        for did, rec in devices.items():
            if not isinstance(rec, dict):
                continue
            ip = str(rec.get("ip") or "").strip()
            if not ip:
                continue
            device_id = str(did).strip()
            ip_by_device[device_id] = ip
            device_by_ip[ip] = device_id
        self._ip_by_device = ip_by_device
        self._device_by_ip = device_by_ip
        self._ip_map_mtime = mtime

    def lookup_ip(self, device_id: str) -> str:
        self._refresh_ip_map()
        return self._ip_by_device.get((device_id or "").strip(), "")

    def lookup_device(self, source_ip: str) -> str:
        self._refresh_ip_map()
        return self._device_by_ip.get((source_ip or "").strip(), "")

    def record(
        self,
        *,
        reason: str,
        device_id: str,
        source_ip: str = "",
        gateway_id: str = "",
        detail: str = "",
        arrival_ms: int | None = None,
    ) -> DenyEvent:
        did = (device_id or "unknown").strip() or "unknown"
        ip = (source_ip or "").strip()
        if not ip:
            ip = self.lookup_ip(did)
        if (not did or did == "unknown") and ip:
            mapped = self.lookup_device(ip)
            if mapped:
                did = mapped
        event = DenyEvent(
            arrival_ms=int(arrival_ms if arrival_ms is not None else time.time() * 1000),
            reason=(reason or "denied").strip() or "denied",
            device_id=did,
            source_ip=ip,
            gateway_id=(gateway_id or self.gateway_id or "").strip(),
            detail=(detail or "").strip()[:240],
        )
        with self._lock:
            self._events.append(event)
            self._append_jsonl(event)
        return event

    def _append_jsonl(self, event: DenyEvent) -> None:
        if self.path is None:
            return
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(event.as_dict(), separators=(",", ":")) + "\n")
        except OSError as exc:
            logger.debug("deny_log write failed: %s", exc)

    def recent(
        self,
        *,
        limit: int = 100,
        device_id: str | None = None,
    ) -> list[dict[str, Any]]:
        lim = max(1, min(int(limit or 100), self.max_events))
        want = (device_id or "").strip() or None
        with self._lock:
            items = list(self._events)
        if want:
            items = [e for e in items if e.device_id == want]
        items = items[-lim:]
        items.reverse()  # newest first
        return [e.as_dict() for e in items]
