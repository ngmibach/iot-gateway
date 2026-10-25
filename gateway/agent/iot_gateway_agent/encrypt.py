"""Fernet encrypt path matching ``decrypt.fernet_decrypt`` / Node-RED K17."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
from typing import Any

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def _b64encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def fernet_encrypt(message: bytes | str | dict[str, Any], key_b64: str) -> str:
    """Seal ``message`` as a Fernet token compatible with ``fernet_decrypt``."""
    if isinstance(message, dict):
        plain = json.dumps(message, ensure_ascii=False, separators=(",", ":")).encode(
            "utf-8"
        )
    elif isinstance(message, str):
        plain = message.encode("utf-8")
    else:
        plain = message

    pad = "=" * (-len(key_b64) % 4)
    key_buf = base64.urlsafe_b64decode(key_b64 + pad)
    if len(key_buf) != 32:
        raise ValueError(f"invalid key length: {len(key_buf)} (expected 32)")

    signing_key, encryption_key = key_buf[:16], key_buf[16:32]
    version = b"\x80"
    timestamp = int(time.time()).to_bytes(8, "big")
    iv = os.urandom(16)
    pad_len = 16 - (len(plain) % 16)
    padded = plain + bytes([pad_len]) * pad_len
    encryptor = Cipher(algorithms.AES(encryption_key), modes.CBC(iv)).encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    body = version + timestamp + iv + ciphertext
    digest = hmac.new(signing_key, body, hashlib.sha256).digest()
    return _b64encode(body + digest)


def encrypt_wrapper_payload(
    payload: Any,
    *,
    key_b64: str | None = None,
) -> str:
    """Return JSON ``{\"key\", \"encrypted\"}`` wrapper string.

    When ``key_b64`` is omitted a fresh 32-byte key is generated (urlsafe b64).
    """
    if key_b64 is None:
        key_b64 = _b64encode(os.urandom(32))
    if isinstance(payload, (bytes, bytearray)):
        message: bytes | str | dict[str, Any] = bytes(payload)
    else:
        message = payload
    token = fernet_encrypt(message, key_b64)
    return json.dumps({"key": key_b64, "encrypted": token}, ensure_ascii=False)


def corrupt_wrapper_payload(payload: Any) -> str:
    """Build a wrapper that fails HMAC / decrypt (bad_encryption behavior)."""
    wrapper = json.loads(encrypt_wrapper_payload(payload))
    enc = wrapper.get("encrypted") or ""
    if len(enc) < 8:
        wrapper["encrypted"] = (enc or "AAAA") + "XXXX"
    else:
        # Flip a middle character so base64 still parses but HMAC fails.
        mid = len(enc) // 2
        flip = "A" if enc[mid] != "A" else "B"
        wrapper["encrypted"] = enc[:mid] + flip + enc[mid + 1 :]
    return json.dumps(wrapper, ensure_ascii=False)
