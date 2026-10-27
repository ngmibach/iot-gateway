"""Unit tests for wizard CA / sudo inject helpers."""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from unittest import mock

from shell import keyring_store
from shell.wizard_server import (
    _gateway_id_from_v1_path,
    _inject_ca_passphrase,
    _inject_sudo_password,
    _should_inject_ca,
    _should_inject_sudo,
)


class CaInjectHelpersTests(unittest.TestCase):
    def setUp(self) -> None:
        self._td = tempfile.TemporaryDirectory()
        self.addCleanup(self._td.cleanup)
        self.env = mock.patch.dict(os.environ, {"IOTGW_DATA_DIR": self._td.name})
        self.env.start()
        self.addCleanup(self.env.stop)
        self.kr = mock.patch.object(
            keyring_store, "_keyring_usable", return_value=False
        )
        self.kr.start()
        self.addCleanup(self.kr.stop)

    def test_path_helpers(self) -> None:
        self.assertEqual(
            _gateway_id_from_v1_path("/api/v1/gateways/gw1/devices"), "gw1"
        )
        self.assertTrue(_should_inject_ca("POST", "/api/v1/gateways/gw1/devices"))
        self.assertFalse(
            _should_inject_ca("POST", "/api/v1/gateways/gw1/devices/discover")
        )
        self.assertTrue(
            _should_inject_ca(
                "POST", "/api/v1/gateways/gw1/devices/s1/reissue-cert"
            )
        )
        self.assertTrue(
            _should_inject_ca("PATCH", "/api/v1/gateways/gw1/devices/s1")
        )
        self.assertTrue(
            _should_inject_ca("POST", "/api/v1/gateways/gw1/devices/fake")
        )
        self.assertTrue(
            _should_inject_ca(
                "POST", "/api/v1/gateways/gw1/devices/fake1/fake/feed-cert"
            )
        )
        self.assertFalse(
            _should_inject_ca(
                "POST", "/api/v1/gateways/gw1/devices/fake1/fake/start"
            )
        )
        self.assertTrue(
            _should_inject_sudo("POST", "/api/v1/gateways/gw1/devices/fake")
        )
        self.assertTrue(
            _should_inject_sudo(
                "POST", "/api/v1/gateways/gw1/devices/fake1/fake/start"
            )
        )
        self.assertTrue(
            _should_inject_sudo(
                "POST", "/api/v1/gateways/gw1/devices/fake1/fake/stop"
            )
        )
        self.assertTrue(
            _should_inject_sudo(
                "PATCH", "/api/v1/gateways/gw1/devices/fake1/fake"
            )
        )
        self.assertTrue(
            _should_inject_sudo("POST", "/api/v1/gateways/gw1/devices")
        )
        self.assertTrue(
            _should_inject_sudo("PATCH", "/api/v1/gateways/gw1/devices/s1")
        )
        self.assertTrue(
            _should_inject_sudo("DELETE", "/api/v1/gateways/gw1/devices/s1")
        )

    def test_inject_merges_keyring(self) -> None:
        keyring_store.set_secret("gw1", "secret-ca", kind="ca")
        body, ct = _inject_ca_passphrase(b'{"user_id":"s1"}', "gw1")
        self.assertEqual(ct, "application/json")
        data = json.loads(body.decode("utf-8"))
        self.assertEqual(data["ca_passphrase"], "secret-ca")
        body2, ct2 = _inject_ca_passphrase(
            b'{"ca_passphrase":"already"}', "gw1"
        )
        self.assertIsNone(ct2)
        self.assertEqual(body2, b'{"ca_passphrase":"already"}')

    def test_inject_sudo_merges_keyring(self) -> None:
        keyring_store.set_secret("gw1", "s3cret-sudo", kind="sudo")
        body, ct = _inject_sudo_password(b'{"user_id":"fake1"}', "gw1")
        self.assertEqual(ct, "application/json")
        data = json.loads(body.decode("utf-8"))
        self.assertEqual(data["sudo_password"], "s3cret-sudo")
        body2, ct2 = _inject_sudo_password(
            b'{"sudo_password":"already"}', "gw1"
        )
        self.assertIsNone(ct2)
        self.assertEqual(body2, b'{"sudo_password":"already"}')


if __name__ == "__main__":
    unittest.main()
