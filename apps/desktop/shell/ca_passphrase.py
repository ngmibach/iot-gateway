"""Generate and validate gateway CA passphrases for Install bootstrap.

Auto-generated passphrases mix operator-provided entropy (sudo password,
gateway id) with time and a random salt, then are stored in the keyring.
They are never re-derived later — keyring is the source of truth.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import time


_APP_SALT = b"iotgw-ca-passphrase-v1"
_MIN_LEN = 24


def generate_ca_passphrase(
    *,
    sudo_password: str,
    gateway_id: str,
    device_password: str = "",
    utc_ns: int | None = None,
    extra_salt: bytes | None = None,
) -> str:
    """Build a strong one-shot CA passphrase and return it (caller stores it).

    Inputs are entropy only (sudo password, optional device/sensor password,
    gateway id). Losing the keyring means the passphrase cannot be recovered
    from those inputs alone.
    """
    if not (sudo_password or "").strip():
        raise ValueError("sudo password required to generate CA passphrase")
    gid = (gateway_id or "").strip() or "gateway"
    stamp = utc_ns if utc_ns is not None else time.time_ns()
    salt = extra_salt if extra_salt is not None else secrets.token_bytes(16)
    material = b"|".join(
        [
            sudo_password.encode("utf-8"),
            (device_password or "").encode("utf-8"),
            gid.encode("utf-8"),
            str(stamp).encode("ascii"),
            salt,
            _APP_SALT,
        ]
    )
    digest = hmac.new(_APP_SALT, material, hashlib.sha256).digest()
    # 32 bytes → ~43 urlsafe chars; strip padding for easier typing if shown later.
    token = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    if len(token) < _MIN_LEN:
        token = token + secrets.token_urlsafe(_MIN_LEN)
    if token == "admin":
        token = token + secrets.token_urlsafe(8)
    return token


def validate_ca_passphrase(passphrase: str, *, reject_admin: bool = True) -> str:
    """Normalize and reject empty / forbidden passphrases."""
    value = (passphrase or "").strip()
    if not value:
        raise ValueError("CA passphrase required")
    if reject_admin and value == "admin":
        raise ValueError("CA passphrase must not be 'admin'")
    return value
