"""SSH pin resolution + user-facing error scrubbing (no key material in UI)."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from api.deps import (
    resolve_ssh_host_pin,
    resolve_ssh_key_path,
    sanitize_user_error,
)
from api.settings import Settings
from actions.ssh import SSHClient, SSHTarget


class SanitizeUserErrorTests(unittest.TestCase):
    def test_redacts_openssh_key_body(self) -> None:
        key = "AAAAC3NzaC1lZDI1NTE5AAAAICGmoZVh+fAh2Lm6O/yyMx3c98oO6pdT5aW2C96IvM6h"
        msg = f"SSH host key mismatch for 172.20.10.2: got {key}"
        out = sanitize_user_error(msg)
        self.assertNotIn(key, out)
        self.assertNotIn("AAAA", out)
        self.assertIn("172.20.10.2", out)
        self.assertIn("host key mismatch", out.lower())

    def test_redacts_sha256_fingerprint(self) -> None:
        out = sanitize_user_error("pin SHA256:abcdef/+1234 failed")
        self.assertNotIn("SHA256:abcdef/+1234", out)
        self.assertIn("[redacted]", out)


class ResolveSshHostPinTests(unittest.TestCase):
    def test_prefers_settings_pin_base64_over_sha256_fingerprint(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "settings.json").write_text(
                json.dumps(
                    {
                        "ssh_host_pins": {
                            "172.20.10.2:22": {
                                "fingerprint_sha256": "SHA256:abc",
                                "base64": "PINNEDBASE64KEYVALUE0000000000001",
                            }
                        }
                    }
                ),
                encoding="utf-8",
            )
            (root / "known_hosts").write_text(
                "172.20.10.2 ssh-ed25519 PINNEDBASE64KEYVALUE0000000000001\n",
                encoding="utf-8",
            )
            settings = Settings(data_dir=root)
            pin, known = resolve_ssh_host_pin(
                settings,
                {
                    "host": "172.20.10.2",
                    "fingerprint": "SHA256:abc",
                },
            )
            self.assertEqual(pin, "PINNEDBASE64KEYVALUE0000000000001")
            self.assertEqual(known, [str(root / "known_hosts")])

    def test_ignores_sha256_registry_fingerprint_without_pin(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            settings = Settings(data_dir=Path(tmp))
            pin, known = resolve_ssh_host_pin(
                settings,
                {"host": "10.0.0.1", "fingerprint": "SHA256:not-a-host-key"},
            )
            self.assertIsNone(pin)
            self.assertEqual(known, [])


class ResolveSshKeyPathTests(unittest.TestCase):
    def test_prefers_env_key_when_file_exists(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            env_key = root / "from-env"
            env_key.write_text("k", encoding="utf-8")
            settings_key = root / "ssh" / "id_ed25519_gateway"
            settings_key.parent.mkdir(parents=True)
            settings_key.write_text("k2", encoding="utf-8")
            (root / "settings.json").write_text(
                json.dumps(
                    {
                        "default_gateway_id": "gateway",
                        "gateways": {
                            "gateway": {
                                "host": "172.20.10.2",
                                "ssh_key_path": str(settings_key),
                            }
                        },
                    }
                ),
                encoding="utf-8",
            )
            settings = Settings(data_dir=root, ssh_key_path=str(env_key))
            got = resolve_ssh_key_path(
                settings, {"id": "gateway", "host": "172.20.10.2"}
            )
            self.assertEqual(got, str(env_key))

    def test_falls_back_to_settings_json_when_env_missing(self) -> None:
        """Control started before Install: IOTGW_SSH_KEY unset, key only in settings."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            key = root / "ssh" / "id_ed25519_gateway"
            key.parent.mkdir(parents=True)
            key.write_text("private", encoding="utf-8")
            (root / "settings.json").write_text(
                json.dumps(
                    {
                        "default_gateway_id": "gateway",
                        "gateways": {
                            "gateway": {
                                "host": "172.20.10.2",
                                "username": "admin",
                                "ssh_key_path": str(key),
                                "password_auth_disabled": True,
                            }
                        },
                    }
                ),
                encoding="utf-8",
            )
            settings = Settings(data_dir=root, ssh_key_path=None)
            got = resolve_ssh_key_path(
                settings, {"id": "gateway", "host": "172.20.10.2", "ssh_user": "admin"}
            )
            self.assertEqual(got, str(key))

    def test_falls_back_to_conventional_data_dir_key(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            key = root / "ssh" / "id_ed25519_gateway"
            key.parent.mkdir(parents=True)
            key.write_text("private", encoding="utf-8")
            settings = Settings(data_dir=root, ssh_key_path=None)
            got = resolve_ssh_key_path(
                settings, {"id": "gateway", "host": "172.20.10.2"}
            )
            self.assertEqual(got, str(key))

    def test_matches_settings_row_by_host_when_id_differs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            key = root / "keyfile"
            key.write_text("private", encoding="utf-8")
            (root / "settings.json").write_text(
                json.dumps(
                    {
                        "gateways": {
                            "gateway": {
                                "host": "172.20.10.2",
                                "ssh_key_path": str(key),
                            }
                        }
                    }
                ),
                encoding="utf-8",
            )
            settings = Settings(data_dir=root, ssh_key_path=None)
            got = resolve_ssh_key_path(
                settings, {"id": "other", "host": "172.20.10.2"}
            )
            self.assertEqual(got, str(key))

    def test_returns_none_when_no_key_available(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            settings = Settings(data_dir=Path(tmp), ssh_key_path=None)
            self.assertIsNone(
                resolve_ssh_key_path(settings, {"id": "gateway", "host": "10.0.0.1"})
            )


class SshMismatchMessageTests(unittest.TestCase):
    def test_mismatch_message_omits_remote_key(self) -> None:
        class FakeKey:
            def get_base64(self) -> str:
                return "AAAAC3NzaC1lZDI1NTE5AAAAIShouldNeverAppearInErrorsXX"

        class FakeTransport:
            def get_remote_server_key(self) -> FakeKey:
                return FakeKey()

        class FakeClient:
            def load_system_host_keys(self) -> None:
                return None

            def load_host_keys(self, path: str) -> None:
                return None

            def set_missing_host_key_policy(self, policy: object) -> None:
                return None

            def connect(self, **kwargs: object) -> None:
                return None

            def get_transport(self) -> FakeTransport:
                return FakeTransport()

            def open_sftp(self) -> object:
                raise AssertionError("should not open sftp after mismatch")

            def close(self) -> None:
                return None

        target = SSHTarget(
            host="172.20.10.2",
            username="admin",
            host_key_base64="EXPECTEDPINNEDKEYVALUE000000000001",
        )
        with mock.patch("actions.ssh.paramiko.SSHClient", FakeClient):
            client = SSHClient(target, transport_retries=0)
            with self.assertRaises(RuntimeError) as ctx:
                client.connect()
        msg = str(ctx.exception)
        self.assertIn("host key mismatch", msg.lower())
        self.assertNotIn("AAAA", msg)
        self.assertNotIn("ShouldNeverAppear", msg)


if __name__ == "__main__":
    unittest.main()
