"""Unit tests for Fernet encrypt / wrapper helpers."""

from __future__ import annotations

import json
import os
import unittest

from iot_gateway_agent.decrypt import decrypt_wrapper_payload, fernet_decrypt
from iot_gateway_agent.encrypt import (
    corrupt_wrapper_payload,
    encrypt_wrapper_payload,
    fernet_encrypt,
)


class EncryptTests(unittest.TestCase):
    def test_roundtrip_with_decrypt(self) -> None:
        import base64

        key = os.urandom(32)
        key_b64 = base64.urlsafe_b64encode(key).decode("ascii").rstrip("=")
        payload = {"sensor": "fake1", "value": 42}
        token = fernet_encrypt(payload, key_b64)
        self.assertEqual(fernet_decrypt(token, key_b64), payload)

        wrapper = encrypt_wrapper_payload(payload, key_b64=key_b64)
        out = decrypt_wrapper_payload(wrapper)
        self.assertIsNotNone(out)
        self.assertEqual(json.loads(out), payload)

    def test_encrypt_wrapper_generates_key(self) -> None:
        wrapper = json.loads(encrypt_wrapper_payload({"hello": 1}))
        self.assertIn("key", wrapper)
        self.assertIn("encrypted", wrapper)
        out = decrypt_wrapper_payload(json.dumps(wrapper))
        self.assertEqual(json.loads(out), {"hello": 1})

    def test_corrupt_wrapper_fails_decrypt(self) -> None:
        bad = corrupt_wrapper_payload({"hello": 1})
        self.assertIsNone(decrypt_wrapper_payload(bad))


if __name__ == "__main__":
    unittest.main()
