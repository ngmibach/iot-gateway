"""Local Mosquitto password hashing — never run mosquitto_passwd -b on the gateway."""

from __future__ import annotations

import base64
import hashlib
import secrets
import subprocess
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


def hash_password_line_via_docker(
    username: str,
    password: str,
    *,
    image: str = "eclipse-mosquitto:2",
) -> str:
    """Hash via ephemeral local container (argv never reaches the gateway)."""
    if not username or ":" in username:
        raise ValueError(f"invalid mosquitto username: {username!r}")
    # Password is on local docker argv only — never forwarded over SSH.
    out = subprocess.check_output(
        [
            "docker",
            "run",
            "--rm",
            image,
            "sh",
            "-c",
            'mosquitto_passwd -b -c /tmp/pw "$1" "$2" >/dev/null && cat /tmp/pw',
            "sh",
            username,
            password,
        ],
        text=True,
        timeout=60,
    )
    line = out.strip().splitlines()[-1].strip()
    if not line.startswith(f"{username}:$"):
        raise RuntimeError(f"unexpected mosquitto_passwd output: {line!r}")
    return line


def zeroize_bytearray(buf: bytearray) -> None:
    for i in range(len(buf)):
        buf[i] = 0


def zeroize_str(_value: str) -> None:
    """API hook after hashing; CPython str is immutable so this is a no-op clear."""
    return
