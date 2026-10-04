"""Local admin unlock (PIN/password in OS keyring) for Code Signing (K16)."""

from __future__ import annotations

import hashlib
import hmac
import secrets
import threading
import time
from dataclasses import dataclass
from typing import Optional

from . import keyring_store

ADMIN_GATEWAY_ID = "local"
ADMIN_KIND = "admin"
DEFAULT_TTL_S = 15 * 60
# Soft online throttle against local /api/admin/unlock brute-force.
_MAX_UNLOCK_FAILURES = 5
_UNLOCK_COOLDOWN_S = 30.0


def _normalize_pin(pin: str) -> str:
    return (pin or "").strip()


def has_admin_pin() -> bool:
    return keyring_store.get_secret(ADMIN_GATEWAY_ID, kind=ADMIN_KIND) is not None


def set_admin_pin(pin: str) -> str:
    """Store admin PIN in keyring. Returns keyring ref (never log pin)."""
    pin = _normalize_pin(pin)
    if len(pin) < 4:
        raise ValueError("admin PIN must be at least 4 characters")
    # Store a hash so a compromised fallback file does not yield the raw PIN.
    digest = hashlib.sha256(b"iotgw-admin-pin:" + pin.encode("utf-8")).hexdigest()
    return keyring_store.set_secret(ADMIN_GATEWAY_ID, digest, kind=ADMIN_KIND)


def verify_admin_pin(pin: str) -> bool:
    stored = keyring_store.get_secret(ADMIN_GATEWAY_ID, kind=ADMIN_KIND)
    if stored is None:
        return False
    digest = hashlib.sha256(
        b"iotgw-admin-pin:" + _normalize_pin(pin).encode("utf-8")
    ).hexdigest()
    return hmac.compare_digest(stored, digest)


def clear_admin_pin() -> None:
    keyring_store.delete_secret(ADMIN_GATEWAY_ID, kind=ADMIN_KIND)


@dataclass
class AdminSession:
    token: str
    expires_at: float

    @property
    def valid(self) -> bool:
        return time.time() < self.expires_at


class AdminGate:
    """In-process unlock session for the wizard/admin HTTP server."""

    def __init__(self, *, ttl_s: int = DEFAULT_TTL_S) -> None:
        self.ttl_s = ttl_s
        self._lock = threading.Lock()
        self._session: Optional[AdminSession] = None
        self._fail_count = 0
        self._cooldown_until = 0.0

    def status(self, token: Optional[str] = None) -> dict:
        with self._lock:
            session = self._session
            unlocked = False
            if session is not None and session.valid and token:
                unlocked = hmac.compare_digest(session.token, token)
            return {
                "has_pin": has_admin_pin(),
                "unlocked": unlocked,
                "expires_at": session.expires_at if unlocked and session else None,
                "ttl_s": self.ttl_s,
            }

    def unlock(self, pin: str) -> str:
        with self._lock:
            now = time.time()
            if now < self._cooldown_until:
                raise ValueError("too many failed unlocks — try again shortly")
            if not has_admin_pin():
                raise ValueError("admin PIN not set — call set_pin first")
            if not verify_admin_pin(pin):
                self._fail_count += 1
                if self._fail_count >= _MAX_UNLOCK_FAILURES:
                    self._cooldown_until = now + _UNLOCK_COOLDOWN_S
                    self._fail_count = 0
                raise ValueError("invalid admin PIN")
            self._fail_count = 0
            token = secrets.token_urlsafe(24)
            self._session = AdminSession(
                token=token, expires_at=now + self.ttl_s
            )
            return token

    def lock(self) -> None:
        with self._lock:
            self._session = None

    def require(self, token: Optional[str]) -> None:
        with self._lock:
            session = self._session
            if session is None or not session.valid:
                raise PermissionError("admin unlock required")
            if not token or not hmac.compare_digest(session.token, token):
                raise PermissionError("invalid or expired admin session")

    def set_pin(self, pin: str, *, unlock: bool = True) -> str:
        # Creating/changing a PIN clears lockout so unlock cannot fail after store.
        with self._lock:
            self._fail_count = 0
            self._cooldown_until = 0.0
        ref = set_admin_pin(pin)
        if unlock:
            return self.unlock(pin)
        return ref
