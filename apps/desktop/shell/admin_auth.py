"""Local admin unlock (PIN/password in OS keyring) for Code Signing (K16)."""

from __future__ import annotations

import hashlib
import hmac
import logging
import secrets
import time
from dataclasses import dataclass
from typing import Optional

from . import keyring_store

logger = logging.getLogger(__name__)

ADMIN_GATEWAY_ID = "local"
ADMIN_KIND = "admin"
PIN_ACCOUNT_SUFFIX = "pin"
DEFAULT_TTL_S = 15 * 60


def _pin_account() -> str:
    return keyring_store.cred_username(ADMIN_GATEWAY_ID, ADMIN_KIND)


def has_admin_pin() -> bool:
    return keyring_store.get_secret(ADMIN_GATEWAY_ID, kind=ADMIN_KIND) is not None


def set_admin_pin(pin: str) -> str:
    """Store admin PIN in keyring. Returns keyring ref (never log pin)."""
    pin = (pin or "").strip()
    if len(pin) < 4:
        raise ValueError("admin PIN must be at least 4 characters")
    # Store a hash so a compromised fallback file does not yield the raw PIN.
    digest = hashlib.sha256(b"iotgw-admin-pin:" + pin.encode("utf-8")).hexdigest()
    return keyring_store.set_secret(ADMIN_GATEWAY_ID, digest, kind=ADMIN_KIND)


def verify_admin_pin(pin: str) -> bool:
    stored = keyring_store.get_secret(ADMIN_GATEWAY_ID, kind=ADMIN_KIND)
    if stored is None:
        return False
    digest = hashlib.sha256(b"iotgw-admin-pin:" + (pin or "").encode("utf-8")).hexdigest()
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
        self._session: Optional[AdminSession] = None

    def status(self, token: Optional[str] = None) -> dict:
        unlocked = False
        if self._session and self._session.valid and token:
            unlocked = hmac.compare_digest(self._session.token, token)
        return {
            "has_pin": has_admin_pin(),
            "unlocked": unlocked,
            "expires_at": self._session.expires_at if unlocked and self._session else None,
            "ttl_s": self.ttl_s,
        }

    def unlock(self, pin: str) -> str:
        if not has_admin_pin():
            raise ValueError("admin PIN not set — call set_pin first")
        if not verify_admin_pin(pin):
            raise ValueError("invalid admin PIN")
        token = secrets.token_urlsafe(24)
        self._session = AdminSession(token=token, expires_at=time.time() + self.ttl_s)
        return token

    def lock(self) -> None:
        self._session = None

    def require(self, token: Optional[str]) -> None:
        if not self._session or not self._session.valid:
            raise PermissionError("admin unlock required")
        if not token or not hmac.compare_digest(self._session.token, token):
            raise PermissionError("invalid or expired admin session")

    def set_pin(self, pin: str, *, unlock: bool = True) -> str:
        ref = set_admin_pin(pin)
        if unlock:
            return self.unlock(pin)
        return ref
