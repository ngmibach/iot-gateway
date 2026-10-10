"""Unit tests for Fernet decrypt (Node-RED replacement)."""

from __future__ import annotations

import base64
import json
import os
import unittest

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from iot_gateway_agent.decrypt import DecryptError, decrypt_wrapper_payload, fernet_decrypt


def _fernet_seal(message: bytes, key: bytes) -> str:
    """Build a Fernet token compatible with decrypt.fernet_decrypt."""
    import hashlib
    import hmac
    import time

    assert len(key) == 32
    signing_key, encryption_key = key[:16], key[16:]
    version = b"\x80"
    timestamp = int(time.time()).to_bytes(8, "big")
    iv = os.urandom(16)
    pad = 16 - (len(message) % 16)
    padded = message + bytes([pad]) * pad
    encryptor = Cipher(algorithms.AES(encryption_key), modes.CBC(iv)).encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    body = version + timestamp + iv + ciphertext
    digest = hmac.new(signing_key, body, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(body + digest).decode("ascii").rstrip("=")


class DecryptTests(unittest.TestCase):
    def test_roundtrip_wrapper(self) -> None:
        key = os.urandom(32)
        key_b64 = base64.urlsafe_b64encode(key).decode("ascii").rstrip("=")
        payload = {"sensor": "s1", "value": 42}
        token = _fernet_seal(json.dumps(payload).encode(), key)
        wrapper = json.dumps({"key": key_b64, "encrypted": token})
        out = decrypt_wrapper_payload(wrapper)
        self.assertIsNotNone(out)
        self.assertEqual(json.loads(out), payload)

    def test_missing_fields_passthrough(self) -> None:
        raw = '{"hello":1}'
        self.assertEqual(json.loads(decrypt_wrapper_payload(raw) or ""), {"hello": 1})

    def test_bad_key_returns_none(self) -> None:
        self.assertIsNone(
            decrypt_wrapper_payload(
                json.dumps({"key": "AAAA", "encrypted": "AAAA"})
            )
        )


if __name__ == "__main__":
    unittest.main()
