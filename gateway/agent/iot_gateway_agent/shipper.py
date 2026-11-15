"""Push sensor_data.log lines to the operator Loki (replaces Promtail)."""

from __future__ import annotations

import json
import logging
import socket
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


class LokiShipper:
    """Tail a log file and POST batches to Loki's push API."""

    def __init__(
        self,
        log_path: Path,
        *,
        loki_url: str,
        job: str = "iot-gateway-agent",
        gateway_label: str | None = None,
        interval_s: float = 2.0,
    ):
        self.log_path = Path(log_path)
        self.loki_url = loki_url.rstrip("/") + "/loki/api/v1/push"
        self.job = job
        self.gateway_label = (gateway_label or "").strip() or socket.gethostname()
        self.interval_s = interval_s
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self.lines_sent = 0

    @property
    def alive(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="loki-shipper", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)
        self._thread = None

    def _run(self) -> None:
        offset = 0
        inode: int | None = None
        pending = b""
        if self.log_path.is_file():
            stat = self.log_path.stat()
            offset = stat.st_size
            inode = int(stat.st_ino)
        while not self._stop.is_set():
            try:
                if self.log_path.is_file():
                    stat = self.log_path.stat()
                    if int(stat.st_ino) != inode or stat.st_size < offset:
                        offset = 0
                        pending = b""
                        inode = int(stat.st_ino)
                    with self.log_path.open("rb") as handle:
                        handle.seek(offset)
                        chunk = handle.read()
                        new_offset = handle.tell()
                    if chunk:
                        parts = (pending + chunk).split(b"\n")
                        complete, next_pending = parts[:-1], parts[-1]
                        lines = [
                            line.decode("utf-8", errors="replace")
                            for line in complete
                            if line.strip()
                        ]
                        if lines:
                            self._push(lines)
                            self.lines_sent += len(lines)
                        pending = next_pending
                        offset = new_offset
            except Exception as e:  # noqa: BLE001
                logger.warning("loki shipper: %s", e)
            self._stop.wait(self.interval_s)

    def _push(self, lines: list[str]) -> None:
        now_ns = str(int(time.time() * 1e9))
        values = [[now_ns, ln] for ln in lines]
        body = {
            "streams": [
                {
                    "stream": {
                        "job": self.job,
                        "agent": "iot-gateway-agent",
                        "gateway": self.gateway_label,
                    },
                    "values": values,
                }
            ]
        }
        req = urllib.request.Request(
            self.loki_url,
            data=json.dumps(body).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                if resp.status >= 300:
                    raise RuntimeError(f"loki push status {resp.status}")
        except urllib.error.URLError as e:
            raise RuntimeError(f"loki push failed: {e}") from e
