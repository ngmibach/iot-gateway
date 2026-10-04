"""Local Mosquitto password hashing — never run mosquitto_passwd -b on the gateway."""

from __future__ import annotations

import base64
import hashlib
import secrets
from typing import Optional

# Matches eclipse-mosquitto 2.x default $7$ (PBKDF2-HMAC-SHA512) output.
_DEFAULT_ITERATIONS = 1000
_SALT_LEN = 64
_DK_LEN = 64


def hash_password_line(
    username: str,
    password: str,
    *,
    iterations: int = _DEFAULT_ITERATIONS,
    salt: Optional[bytes] = None,
) -> str:
    """Return ``user:$7$iterations$salt_b64$hash_b64`` using PBKDF2-HMAC-SHA512."""
    if not username or ":" in username or "\n" in username or " " in username:
        raise ValueError(f"invalid mosquitto username: {username!r}")
    if not password:
        raise ValueError("password must be non-empty")
    salt_b = salt if salt is not None else secrets.token_bytes(_SALT_LEN)
    if len(salt_b) != _SALT_LEN:
        raise ValueError(f"salt must be {_SALT_LEN} bytes")
    dk = hashlib.pbkdf2_hmac(
        "sha512",
        password.encode("utf-8"),
        salt_b,
        iterations,
        dklen=_DK_LEN,
    )
    return (
        f"{username}:$7${iterations}$"
        f"{base64.b64encode(salt_b).decode('ascii')}$"
        f"{base64.b64encode(dk).decode('ascii')}"
    )


def zeroize_str(_value: str) -> None:
    """Best-effort API hook after hashing.

    CPython ``str`` is immutable, so this cannot clear the caller's plaintext.
    Prefer passing secrets as ``bytearray`` at call sites when feasible.
    """
    return
