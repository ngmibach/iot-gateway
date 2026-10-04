"""Keyring + file-fallback secret storage."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from shell import keyring_store


class KeyringStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self._td = tempfile.TemporaryDirectory()
        self.addCleanup(self._td.cleanup)
        self.data = Path(self._td.name)
        self.env = mock.patch.dict(os.environ, {"IOTGW_DATA_DIR": str(self.data)})
        self.env.start()
        self.addCleanup(self.env.stop)
        # Force fallback path (no usable OS keyring in CI).
        self.kr_usable = mock.patch.object(
            keyring_store, "_keyring_usable", return_value=False
        )
        self.kr_usable.start()
        self.addCleanup(self.kr_usable.stop)

    def test_set_get_delete(self) -> None:
        ref = keyring_store.set_secret("gw1", "s3cret")
        self.assertTrue(ref.startswith("file:"))
        self.assertEqual(keyring_store.get_secret(ref), "s3cret")
        self.assertEqual(keyring_store.get_secret("gw1"), "s3cret")
        path = keyring_store._fallback_path()
        self.assertTrue(path.is_file())
        mode = path.stat().st_mode & 0o777
        self.assertEqual(mode, 0o600)
        keyring_store.delete_secret("gw1")
        self.assertIsNone(keyring_store.get_secret("gw1"))


if __name__ == "__main__":
    unittest.main()
