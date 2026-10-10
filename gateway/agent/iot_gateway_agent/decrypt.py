"""Fernet decrypt path (replaces Node-RED K17 decrypt → sensor_data.log)."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
from typing import Any

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

logger = logging.getLogger(__name__)


class DecryptError(ValueError):
    """Invalid token or key."""


def _b64decode(data: str) -> bytes:
    """Decode std or urlsafe base64, with optional missing padding."""
    s = data.strip()
    pad = "=" * (-len(s) % 4)
    for decoder in (base64.urlsafe_b64decode, base64.b64decode):
        try:
            return decoder(s + pad)
        except Exception:
            continue
    raise DecryptError("invalid base64")


def fernet_decrypt(token_b64: str, key_b64: str) -> Any:
    """Decrypt a Fernet token; return parsed JSON object.

    Matches ``gateway/nodered/decrypt_function.js`` (full-message encrypt).
    """
    key_buf = _b64decode(key_b64)
    if len(key_buf) != 32:
        raise DecryptError(f"invalid key length: {len(key_buf)} (expected 32)")

    signing_key = key_buf[:16]
    encryption_key = key_buf[16:32]
    token_buf = _b64decode(token_b64)
    if len(token_buf) < 57:
        raise DecryptError(f"token too short: {len(token_buf)}")
    if token_buf[0] != 0x80:
        raise DecryptError(f"unsupported Fernet version: 0x{token_buf[0]:02x}")

    hmac_data = token_buf[:-32]
    hmac_given = token_buf[-32:]
    hmac_calc = hmac.new(signing_key, hmac_data, hashlib.sha256).digest()
    if not hmac.compare_digest(hmac_given, hmac_calc):
        raise DecryptError("HMAC verification failed — wrong key or corrupted data")

    iv = token_buf[9:25]
    ciphertext = token_buf[25:-32]
    decryptor = Cipher(algorithms.AES(encryption_key), modes.CBC(iv)).decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    pad = padded[-1]
    if pad < 1 or pad > 16 or padded[-pad:] != bytes([pad]) * pad:
        raise DecryptError("invalid PKCS7 padding")
    plain = padded[:-pad]
    return json.loads(plain.decode("utf-8"))


def decrypt_wrapper_payload(payload: str | bytes | dict) -> str | None:
    """Decrypt sensor wrapper JSON; return JSON string or None on failure."""
    try:
        if isinstance(payload, (bytes, bytearray)):
            payload = payload.decode("utf-8")
        wrapper = json.loads(payload) if isinstance(payload, str) else payload
        if not isinstance(wrapper, dict):
            return json.dumps(wrapper)
        key = wrapper.get("key")
        encrypted = wrapper.get("encrypted")
        if not key or not encrypted:
            return json.dumps(wrapper)
        decrypted = fernet_decrypt(str(encrypted), str(key))
        return json.dumps(decrypted, ensure_ascii=False)
    except Exception as e:  # noqa: BLE001
        logger.warning("decryption failed: %s", e)
        return None
