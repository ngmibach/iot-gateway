"""Tail Mosquitto logs for Denied PUBLISH / ACL rejects → per-device counters."""

from __future__ import annotations

import logging
import re
import threading
from pathlib import Path
from typing import TYPE_CHECKING, Callable, Optional

if TYPE_CHECKING:
    from .decrypt_worker import DecryptWorker

logger = logging.getLogger(__name__)

# Mosquitto classic: "Denied PUBLISH from sensor1 (ACL deny) ..."
# Also match "Denied PUBLISH ... user sensor1" variants.
_DENIED_RE = re.compile(
    r"Denied PUBLISH.*?((?:from|user)\s+)([A-Za-z0-9_.\-]+)",
    re.IGNORECASE,
)
_IDS_RE = re.compile(
    r"(?:ids[_ ]?alert|intrusion|anomaly).*?(?:device[_ ]?id[=: ]+|user[=: ]+)?"
    r"([A-Za-z0-9_.\-]+)?",
    re.IGNORECASE,
)

_DEFAULT_LOG_CANDIDATES = (
    "/var/lib/iot-gateway-agent/mosquitto/log/mosquitto.log",
    "/var/log/mosquitto/mosquitto.log",
    "/var/log/mosquitto.log",
)


class DeniedWatcher:
    """Follow Mosquitto (and optional IDS) log files; bump agent counters."""

    def __init__(
        self,
        *,
        worker: "DecryptWorker",
        log_paths: list[str | Path] | None = None,
        ids_log_paths: list[str | Path] | None = None,
    ):
        self.worker = worker
        self.log_paths = [Path(p) for p in (log_paths or _DEFAULT_LOG_CANDIDATES)]
        self.ids_log_paths = [Path(p) for p in (ids_log_paths or [])]
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self.denied_total = 0
        self.ids_total = 0

    @property
    def alive(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._run, name="denied-watcher", daemon=True
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=3)
        self._thread = None

    def _run(self) -> None:
        # Pick first existing mosquitto log; wait until one appears.
        path: Optional[Path] = None
        while not self._stop.is_set() and path is None:
            for candidate in self.log_paths:
                if candidate.is_file():
                    path = candidate
                    break
            if path is None:
                self._stop.wait(2.0)
        if path is None or self._stop.is_set():
            return
        logger.info("denied watcher following %s", path)
        self._follow(path, self._on_mosquitto_line)
        # IDS optional files are best-effort polled in the same loop via reopen.
        for ids_path in self.ids_log_paths:
            if ids_path.is_file():
                # Sequential follow only if mosquitto ends; usually IDS is empty.
                self._follow(ids_path, self._on_ids_line)

    def _follow(self, path: Path, on_line: Callable[[str], None]) -> None:
        try:
            with path.open("r", encoding="utf-8", errors="replace") as f:
                f.seek(0, 2)  # start at end (only new denies)
                while not self._stop.is_set():
                    line = f.readline()
                    if line:
                        on_line(line)
                        continue
                    # Handle truncation/rotation.
                    try:
                        if path.stat().st_size < f.tell():
                            f.seek(0)
                    except OSError:
                        pass
                    self._stop.wait(0.5)
        except OSError as exc:
            logger.warning("denied watcher stopped reading %s: %s", path, exc)

    def _on_mosquitto_line(self, line: str) -> None:
        m = _DENIED_RE.search(line)
        if not m:
            return
        device_id = m.group(2).strip() or "unknown"
        self.denied_total += 1
        self.worker.bump_denied(device_id)

    def _on_ids_line(self, line: str) -> None:
        m = _IDS_RE.search(line)
        if not m:
            return
        device_id = (m.group(1) or "unknown").strip() or "unknown"
        self.ids_total += 1
        self.worker.bump_ids(device_id)
