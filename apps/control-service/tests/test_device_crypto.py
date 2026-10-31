"""Tests for envelope device crypto provisioning helpers."""

from __future__ import annotations

import json
import unittest
import zipfile
from io import BytesIO

from actions.device_crypto import (
    assemble_cert_bundle,
    envelope_acl_topic,
    generate_device_crypto_dict,
)


class DeviceCryptoTests(unittest.TestCase):
    def test_generate_psk(self) -> None:
        secrets = generate_device_crypto_dict("sensor1", profile="v1-psk")
        self.assertEqual(secrets["device_id"], "sensor1")
        self.assertEqual(secrets["profile"], "v1-psk")
        self.assertIn("mac_key", secrets)
        self.assertIn("wrap_secret", secrets)

    def test_envelope_acl_expands_process_topic(self) -> None:
        self.assertEqual(
            envelope_acl_topic("e2eok1", "sensors/e2eok1/process", crypto_profile="v1-psk"),
            "sensors/e2eok1/#",
        )
        self.assertEqual(
            envelope_acl_topic("e2eok1", None, crypto_profile="v1-psk"),
            "sensors/e2eok1/#",
        )
        self.assertEqual(
            envelope_acl_topic("e2eok1", "sensors/e2eok1/#", crypto_profile="v1-psk"),
            "sensors/e2eok1/#",
        )
        self.assertEqual(
            envelope_acl_topic("e2eok1", "sensors/e2eok1/v2/#", crypto_profile="v1-psk"),
            "sensors/e2eok1/v2/#",
        )
        # Non-envelope profiles keep the caller topic unchanged.
        self.assertEqual(
            envelope_acl_topic("e2eok1", "sensors/e2eok1/process", crypto_profile="legacy"),
            "sensors/e2eok1/process",
        )

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
