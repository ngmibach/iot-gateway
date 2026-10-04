"""Pin-required install + SSHClient host_key_base64 handshake policy."""

from __future__ import annotations

import os
import tempfile
import unittest
from unittest import mock

from shell import ssh_setup
from shell.ssh_setup import HostKeyInfo


class RequirePinTests(unittest.TestCase):
    def setUp(self) -> None:
        self._td = tempfile.TemporaryDirectory()
        self.addCleanup(self._td.cleanup)
        self.env = mock.patch.dict(os.environ, {"IOTGW_DATA_DIR": self._td.name})
        self.env.start()
        self.addCleanup(self.env.stop)

    def test_resolve_requires_pin(self) -> None:
        with self.assertRaises(ValueError) as ctx:
            ssh_setup.resolve_required_pin("10.0.0.1", 22, "AAAA")
        self.assertIn("pinned", str(ctx.exception).lower())

    def test_resolve_after_pin(self) -> None:
        info = HostKeyInfo(
            host="10.0.0.1",
            port=22,
            key_type="ssh-ed25519",
            fingerprint_sha256="SHA256:x",
            base64="PINNEDKEY",
        )
        ssh_setup.pin_host_key(info)
        self.assertEqual(
            ssh_setup.resolve_required_pin("10.0.0.1", 22, "PINNEDKEY"),
            "PINNEDKEY",
        )
        with self.assertRaises(ValueError):
            ssh_setup.resolve_required_pin("10.0.0.1", 22, "OTHER")

    def test_settings_mode_0600(self) -> None:
        from shell.paths import save_settings, settings_path

        save_settings({"monitoring_ip": "10.0.0.2"})
        mode = settings_path().stat().st_mode & 0o777
        self.assertEqual(mode, 0o600)


class SSHClientPinPolicyTests(unittest.TestCase):
    def test_host_key_base64_uses_warning_not_reject(self) -> None:
        import paramiko
        from actions.ssh import SSHClient, SSHTarget

        policies: list[object] = []

        class FakeClient:
            def load_system_host_keys(self) -> None:
                return None

            def load_host_keys(self, path: str) -> None:
                return None

            def set_missing_host_key_policy(self, policy: object) -> None:
                policies.append(policy)

            def connect(self, **kwargs: object) -> None:
                raise RuntimeError("stop-before-auth")

            def close(self) -> None:
                return None

        target = SSHTarget(
            host="192.0.2.9",
            username="u",
            password="p",
            host_key_base64="ABC",
            known_hosts_paths=["/nonexistent/known_hosts"],
            allow_unknown_host=False,
        )
        with mock.patch("actions.ssh.paramiko.SSHClient", FakeClient):
            client = SSHClient(target, transport_retries=0)
            with self.assertRaises(RuntimeError):
                client.connect()

        self.assertEqual(len(policies), 1)
        self.assertIsInstance(policies[0], paramiko.WarningPolicy)

    def test_no_pin_uses_reject(self) -> None:
        import paramiko
        from actions.ssh import SSHClient, SSHTarget

        policies: list[object] = []

        class FakeClient:
            def load_system_host_keys(self) -> None:
                return None

            def load_host_keys(self, path: str) -> None:
                return None

            def set_missing_host_key_policy(self, policy: object) -> None:
                policies.append(policy)

            def connect(self, **kwargs: object) -> None:
                raise RuntimeError("stop")

            def close(self) -> None:
                return None

        target = SSHTarget(
            host="192.0.2.9",
            username="u",
            password="p",
            allow_unknown_host=False,
        )
        with mock.patch("actions.ssh.paramiko.SSHClient", FakeClient):
            client = SSHClient(target, transport_retries=0)
            with self.assertRaises(RuntimeError):
                client.connect()

        self.assertIsInstance(policies[0], paramiko.RejectPolicy)


if __name__ == "__main__":
    unittest.main()
