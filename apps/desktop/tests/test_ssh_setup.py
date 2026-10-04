"""SSH key generation + host-key pin (no live SSH)."""

from __future__ import annotations

import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from shell import ssh_setup
from shell.ssh_setup import HostKeyInfo


@unittest.skipUnless(shutil.which("ssh-keygen"), "ssh-keygen required")
class Ed25519Tests(unittest.TestCase):
    def setUp(self) -> None:
        self._td = tempfile.TemporaryDirectory()
        self.addCleanup(self._td.cleanup)
        self.env = mock.patch.dict(os.environ, {"IOTGW_DATA_DIR": self._td.name})
        self.env.start()
        self.addCleanup(self.env.stop)

    def test_generate_idempotent(self) -> None:
        p1 = ssh_setup.generate_ed25519("lab")
        self.assertTrue(p1.private.is_file())
        self.assertTrue(p1.public.is_file())
        pub = p1.public.read_text(encoding="utf-8")
        self.assertIn("ssh-ed25519", pub)
        p2 = ssh_setup.generate_ed25519("lab")
        self.assertEqual(p1.private, p2.private)
        self.assertEqual(pub, p2.public.read_text(encoding="utf-8"))


class PinHostKeyTests(unittest.TestCase):
    def setUp(self) -> None:
        self._td = tempfile.TemporaryDirectory()
        self.addCleanup(self._td.cleanup)
        self.env = mock.patch.dict(os.environ, {"IOTGW_DATA_DIR": self._td.name})
        self.env.start()
        self.addCleanup(self.env.stop)

    def test_pin_writes_known_hosts_and_settings(self) -> None:
        info = HostKeyInfo(
            host="192.168.1.10",
            port=22,
            key_type="ssh-ed25519",
            fingerprint_sha256="SHA256:abc",
            base64="AAAA",
        )
        ssh_setup.pin_host_key(info)
        kh = Path(self._td.name) / "known_hosts"
        text = kh.read_text(encoding="utf-8")
        self.assertIn("192.168.1.10 ssh-ed25519 AAAA", text)
        # Re-pin replaces
        info2 = HostKeyInfo(
            host="192.168.1.10",
            port=22,
            key_type="ssh-ed25519",
            fingerprint_sha256="SHA256:def",
            base64="BBBB",
        )
        ssh_setup.pin_host_key(info2)
        text2 = kh.read_text(encoding="utf-8")
        self.assertIn("BBBB", text2)
        self.assertNotIn("AAAA", text2)


if __name__ == "__main__":
    unittest.main()
