"""Tail Mosquitto logs for Denied PUBLISH / TLS / auth rejects → counters + deny log."""

from __future__ import annotations

import logging
import re
import threading
from pathlib import Path
from typing import TYPE_CHECKING, Callable, Optional

if TYPE_CHECKING:
    from .decrypt_worker import DecryptWorker
    from .deny_log import DenyLog

logger = logging.getLogger(__name__)

# Mosquitto classic: "Denied PUBLISH from sensor1 (ACL deny) ..."
# Also match "Denied PUBLISH ... user sensor1" variants.
_DENIED_RE = re.compile(
    r"Denied PUBLISH.*?((?:from|user)\s+)([A-Za-z0-9_.\-]+)",
    re.IGNORECASE,
)
_NEW_CONN_RE = re.compile(
    r"New connection from ([0-9a-fA-F:.]+):\d+ on port \d+",
    re.IGNORECASE,
)
_CONN_FAILED_RE = re.compile(
    r"Client connection from ([0-9a-fA-F:.]+) failed:\s*(.+)$",
    re.IGNORECASE,
)
_OPENSSL_RE = re.compile(r"OpenSSL Error\[\d+\]:\s*(.+)$", re.IGNORECASE)
_BAD_AUTH_RE = re.compile(
    r"(?:Bad username or password|not authorised|not authorized|"
    r"Connection Refused:\s*not authorized)",
    re.IGNORECASE,
)
# "Client iotgw-fake-fake2 disconnected, not authorised."
# "Client fake2 disconnected, not authorised."
_CLIENT_NAME_RE = re.compile(
    r"Client\s+([A-Za-z0-9_.\-]+)\s+(?:disconnected|denied|closed)",
    re.IGNORECASE,
)
_FAKE_CLIENT_RE = re.compile(r"^iotgw-fake-(.+)$")
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

_LOCAL_IPS = frozenset({"127.0.0.1", "::1", "0.0.0.0"})


def _classify_tls_detail(detail: str) -> str:
    low = (detail or "").lower()
    if "peer did not return a certificate" in low or "no certificate" in low:
        return "missing_client_cert"
    if (
        "certificate verify failed" in low
        or "unknown ca" in low
        or "alert bad certificate" in low
        or "alert unknown ca" in low
        or "certificate required" in low
    ):
        return "bad_client_cert"
    if "unexpected eof" in low:
        return "tls_eof"
    if "protocol error" in low:
        return "tls_protocol"
    return "tls_handshake"


class DeniedWatcher:
    """Follow Mosquitto (and optional IDS) log files; bump agent counters."""

    def __init__(
        self,
        *,
        worker: "DecryptWorker",
        log_paths: list[str | Path] | None = None,
        ids_log_paths: list[str | Path] | None = None,
        deny_log: "DenyLog | None" = None,
    ):
        self.worker = worker
        self.log_paths = [Path(p) for p in (log_paths or _DEFAULT_LOG_CANDIDATES)]
        self.ids_log_paths = [Path(p) for p in (ids_log_paths or [])]
        self.deny_log = deny_log
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self.denied_total = 0
        self.ids_total = 0
        self._last_conn_ip: str = ""

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
        """Follow ``path`` in binary mode.

        Text-mode ``tell()`` returns an opaque cookie that is often larger than
        ``st_size``, which previously tripped the rotation check and rewound the
        watcher to byte 0 — flooding Denied counters from historical log lines.
        """
        try:
            with path.open("rb") as f:
                f.seek(0, 2)  # start at end (only new denies)
                buf = b""
                while not self._stop.is_set():
                    chunk = f.read(8192)
                    if chunk:
                        buf += chunk
                        while b"\n" in buf:
                            raw, buf = buf.split(b"\n", 1)
                            line = raw.decode("utf-8", errors="replace")
                            on_line(line)
                        continue
                    # Truncation / rotation: byte size shrank under our offset.
                    try:
                        size = path.stat().st_size
                        pos = f.tell()
                        if size < pos:
                            f.seek(0)
                            buf = b""
                    except OSError:
                        pass
                    self._stop.wait(0.5)
        except OSError as exc:
            logger.warning("denied watcher stopped reading %s: %s", path, exc)

    @staticmethod
    def _device_from_client_name(name: str) -> str:
        raw = (name or "").strip()
        if not raw or raw in {"<unknown>", "unknown"}:
            return "unknown"
        m = _FAKE_CLIENT_RE.match(raw)
        if m:
            return m.group(1).strip() or "unknown"
        return raw

    def _emit_deny(
        self,
        *,
        device_id: str,
        reason: str,
        source_ip: str = "",
        detail: str = "",
        count_as_message: bool = False,
    ) -> None:
        self.denied_total += 1
        self.worker.bump_denied(
            device_id,
            reason=reason,
            source_ip=source_ip,
            detail=detail,
            count_as_message=count_as_message,
        )

    def _on_mosquitto_line(self, line: str) -> None:
        text = line.strip()
        if not text:
            return

        m_new = _NEW_CONN_RE.search(text)
        if m_new:
            ip = m_new.group(1).strip()
            self._last_conn_ip = "" if ip in _LOCAL_IPS else ip
            return

        m_denied = _DENIED_RE.search(text)
        if m_denied:
            # Mosquitto logs the client id ("iotgw-fake-fake2"), not the MQTT user.
            device_id = self._device_from_client_name(m_denied.group(2))
            self._emit_deny(
                device_id=device_id,
                reason="acl_deny",
                source_ip=self._last_conn_ip,
                detail=text[:200],
                count_as_message=True,
            )
            return

        m_fail = _CONN_FAILED_RE.search(text)
        if m_fail:
            ip = m_fail.group(1).strip()
            if ip in _LOCAL_IPS:
                return
            detail = m_fail.group(2).strip()
            reason = _classify_tls_detail(detail)
            if reason == "tls_eof":
                # Common benign disconnect noise; still count handshake-ish fails.
                pass
            device_id = "unknown"
            if self.deny_log is not None:
                device_id = self.deny_log.lookup_device(ip) or "unknown"
            self._emit_deny(
                device_id=device_id,
                reason=reason,
                source_ip=ip,
                detail=detail[:200],
                count_as_message=True,
            )
            return

        m_ssl = _OPENSSL_RE.search(text)
        if m_ssl:
            ip = self._last_conn_ip
            if not ip or ip in _LOCAL_IPS:
                return
            detail = m_ssl.group(1).strip()
            reason = _classify_tls_detail(detail)
            device_id = "unknown"
            if self.deny_log is not None:
                device_id = self.deny_log.lookup_device(ip) or "unknown"
            self._emit_deny(
                device_id=device_id,
                reason=reason,
                source_ip=ip,
                detail=detail[:200],
                count_as_message=True,
            )
            # Avoid double-counting the following "Client <unknown> disconnected".
            self._last_conn_ip = ""
            return

        if _BAD_AUTH_RE.search(text):
            device_id = "unknown"
            m_client = _CLIENT_NAME_RE.search(text)
            if m_client:
                device_id = self._device_from_client_name(m_client.group(1))
            if device_id == "unknown" and self._last_conn_ip:
                if self.deny_log is not None:
                    device_id = self.deny_log.lookup_device(self._last_conn_ip) or "unknown"
            # Mosquitto may say "not authorised" for ACL publish denies too.
            reason = "acl_deny" if "Denied PUBLISH" in text else "bad_password"
            if "not authorised" in text.lower() or "not authorized" in text.lower():
                # Prefer ACL when the classic Denied PUBLISH form is present;
                # otherwise treat as auth failure (wrong password / not allowed).
                if "Denied PUBLISH" in text:
                    reason = "acl_deny"
                else:
                    reason = "bad_password"
            self._emit_deny(
                device_id=device_id,
                reason=reason,
                source_ip=self._last_conn_ip,
                detail=text[:200],
                count_as_message=True,
            )

    def _on_ids_line(self, line: str) -> None:
        m = _IDS_RE.search(line)
        if not m:
            return
        device_id = (m.group(1) or "unknown").strip() or "unknown"
        self.ids_total += 1
        self.worker.bump_ids(device_id)
