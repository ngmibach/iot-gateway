"""Push sensor_data.log lines to the operator Loki (replaces Promtail)."""

from __future__ import annotations

import json
import logging
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)
_FILE_SIGNATURE_BYTES = 128


def _file_signature(path: Path, offset: int) -> tuple[bytes, bytes]:
    if offset <= 0:
        return b"", b""
    length = min(_FILE_SIGNATURE_BYTES, offset)
    with path.open("rb") as fh:
        prefix = fh.read(length)
        fh.seek(offset - length)
        suffix = fh.read(length)
    return prefix, suffix


class LokiShipper:
    """Tail a log file and POST batches to Loki's push API."""

    def __init__(
        self,
        log_path: Path,
        *,
        loki_url: str,
        job: str = "iot-gateway-agent",
        interval_s: float = 2.0,
        extra_labels: dict[str, str] | None = None,
    ):
        self.log_path = Path(log_path)
        self.loki_url = loki_url.rstrip("/") + "/loki/api/v1/push"
        self.job = job
        self.interval_s = interval_s
        self.extra_labels = dict(extra_labels or {})
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
        partial = b""
        signature = (b"", b"")
        if self.log_path.is_file():
            state = self.log_path.stat()
            offset = state.st_size
            inode = int(state.st_ino)
            signature = _file_signature(self.log_path, offset)
        while not self._stop.is_set():
            try:
                if self.log_path.is_file():
                    state = self.log_path.stat()
                    if inode is None:
                        inode = int(state.st_ino)
                        offset = 0
                    elif int(state.st_ino) != inode or state.st_size < offset:
                        inode = int(state.st_ino)
                        offset = 0
                        partial = b""
                        signature = (b"", b"")
                    elif state.st_size < offset:
                        offset = 0
                        partial = b""
                        signature = (b"", b"")
                    elif offset and signature != _file_signature(
                        self.log_path, offset
                    ):
                        offset = 0
                        partial = b""
                        signature = (b"", b"")
                    with self.log_path.open("rb") as fh:
                        fh.seek(offset)
                        chunk = fh.read()
                        offset = int(fh.tell())
                    signature = _file_signature(self.log_path, offset)
                    if chunk:
                        pieces = (partial + chunk).split(b"\n")
                        partial = pieces.pop()
                        lines = [
                            line.rstrip(b"\r").decode("utf-8", errors="replace")
                            for line in pieces
                            if line.strip()
                        ]
                        if lines:
                            self._push(lines)
                            self.lines_sent += len(lines)
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
                        **self.extra_labels,
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
