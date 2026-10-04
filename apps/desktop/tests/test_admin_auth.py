"""Admin PIN unlock + keyring storage."""

from __future__ import annotations

import os
import tempfile
import unittest
from unittest import mock

from shell import admin_auth, keyring_store


class AdminAuthTests(unittest.TestCase):
    def setUp(self) -> None:
        self._td = tempfile.TemporaryDirectory()
        self.addCleanup(self._td.cleanup)
        self.env = mock.patch.dict(os.environ, {"IOTGW_DATA_DIR": self._td.name})
        self.env.start()
        self.addCleanup(self.env.stop)
        self.krring = mock.patch.object(
            keyring_store, "_keyring_usable", return_value=False
        )
        self.krring.start()
        self.addCleanup(self.krring.stop)
        admin_auth.clear_admin_pin()

    def test_set_verify_unlock(self) -> None:
        self.assertFalse(admin_auth.has_admin_pin())
        gate = admin_auth.AdminGate(ttl_s=60)
        token = gate.set_pin("1234")
        self.assertTrue(admin_auth.has_admin_pin())
        self.assertTrue(gate.status(token)["unlocked"])
        self.assertFalse(gate.status("wrong")["unlocked"])
        gate.lock()
        self.assertFalse(gate.status(token)["unlocked"])
        with self.assertRaises(ValueError):
            gate.unlock("nope")
        token2 = gate.unlock("1234")
        gate.require(token2)
        with self.assertRaises(PermissionError):
            gate.require("bad")

    def test_pin_too_short(self) -> None:
        with self.assertRaises(ValueError):
            admin_auth.set_admin_pin("12")

    def test_pin_stored_hashed(self) -> None:
        admin_auth.set_admin_pin("9999")
        raw = keyring_store.get_secret("local", kind="admin")
        self.assertIsNotNone(raw)
        self.assertNotEqual(raw, "9999")
