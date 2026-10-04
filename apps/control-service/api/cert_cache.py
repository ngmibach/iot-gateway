"""One-time cert-bundle download tokens (memory; ≤5 min or first GET)."""

from __future__ import annotations

import secrets
import threading
import time
from dataclasses import dataclass


DEFAULT_TTL_S = 300


@dataclass
class _Entry:
    gateway_id: str
    device_id: str
    blob: bytes
    expires_at: float


class CertBundleCache:
    def __init__(self, ttl_s: int = DEFAULT_TTL_S) -> None:
        self._ttl = max(1, int(ttl_s))
        self._lock = threading.Lock()
        self._items: dict[str, _Entry] = {}

    def put(self, gateway_id: str, device_id: str, blob: bytes) -> str:
        token = secrets.token_urlsafe(24)
        with self._lock:
            self._purge_locked()
            self._items[token] = _Entry(
                gateway_id=gateway_id,
                device_id=device_id,
                blob=blob,
                expires_at=time.monotonic() + self._ttl,
            )
        return token

    def pop(
        self,
        token: str,
        *,
        gateway_id: str,
        device_id: str,
    ) -> bytes | None:
        with self._lock:
            self._purge_locked()
            entry = self._items.get(token)
            if entry is None:
                return None
            if entry.gateway_id != gateway_id or entry.device_id != device_id:
                return None
            del self._items[token]
            return entry.blob

    def _purge_locked(self) -> None:
        now = time.monotonic()
        dead = [k for k, v in self._items.items() if v.expires_at <= now]
        for k in dead:
            del self._items[k]
