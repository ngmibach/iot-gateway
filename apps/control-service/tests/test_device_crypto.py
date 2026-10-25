"""Tests for envelope device crypto provisioning helpers."""

from __future__ import annotations

import json
import unittest
import zipfile
from io import BytesIO

from actions.device_crypto import (
    assemble_cert_bundle,
    generate_device_crypto_dict,
)


class DeviceCryptoTests(unittest.TestCase):
    def test_generate_psk(self) -> None:
        secrets = generate_device_crypto_dict("sensor1", profile="v1-psk")
        self.assertEqual(secrets["device_id"], "sensor1")
        self.assertEqual(secrets["profile"], "v1-psk")
        self.assertIn("mac_key", secrets)
        self.assertIn("wrap_secret", secrets)

    def test_bundle_includes_crypto(self) -> None:
        secrets = generate_device_crypto_dict("s1")
        blob = assemble_cert_bundle(
            ca_crt_pem=b"CA",
            client_crt_pem=b"CRT",
            client_key_pem=b"KEY",
            crypto_json=secrets,
            schema_json={"schema_id": "default", "type": "object"},
        )
        with zipfile.ZipFile(BytesIO(blob)) as zf:
            names = set(zf.namelist())
            self.assertEqual(
                names, {"ca.crt", "client.crt", "client.key", "crypto.json", "schema.json"}
            )
            loaded = json.loads(zf.read("crypto.json"))
            self.assertEqual(loaded["device_id"], "s1")


if __name__ == "__main__":
    unittest.main()
