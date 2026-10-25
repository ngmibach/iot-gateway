"""Playbook unit tests with mocked SSH."""

from __future__ import annotations

import unittest

from actions.csr import generate_client_key_and_csr
from actions.playbooks import (
    clear_logs,
    register_device,
    unregister_device,
    update_acl,
)
from actions.ssh import CommandResult
from tests.cert_helpers import local_self_sign_for_tests
from tests.fake_ssh import FakeSSH

INSTALL = "/opt/iot-gateway-agent"
DATA = "/var/lib/iot-gateway-agent"
ACL = f"{DATA}/mosquitto/acl"
PW = f"{DATA}/mosquitto/passwords"
CA = f"{DATA}/certs/ca.crt"

BASE_ACL = """user nodered
topic readwrite #

user sensor1
topic readwrite sensors/sensor1/#
topic read alerts/+

user anonymous
topic none
"""

BASE_PW = """nodered:$7$1000$aaa$bbb
sensor1:$7$1000$ccc$ddd
"""


def _base_files() -> dict[str, str]:
    return {
        ACL: BASE_ACL,
        PW: BASE_PW,
        CA: "-----BEGIN CERTIFICATE-----\nCA\n-----END CERTIFICATE-----\n",
        f"{DATA}/certs/ca.key": "-----BEGIN ENCRYPTED PRIVATE KEY-----\nX\n-----END ENCRYPTED PRIVATE KEY-----\n",
    }


def _register_ok_handler(ssh: FakeSSH, signed_pem: bytes):
    def run_handler(cmd: str) -> CommandResult:
        if "openssl x509 -req" in cmd:
            parts = cmd.split()
            out_path = parts[parts.index("-out") + 1].strip("'")
            ssh.files[out_path] = signed_pem
        return CommandResult(argv=cmd, exit_code=0, stdout="", stderr="")

    return run_handler


class TestRegisterDevice(unittest.TestCase):
    def test_register_happy_path(self) -> None:
        ssh = FakeSSH(_base_files())
        mat = generate_client_key_and_csr("sensor9")
        signed = local_self_sign_for_tests(mat)
        ssh._run_handler = _register_ok_handler(ssh, signed.client_crt_pem)

        result = register_device(
            ssh,  # type: ignore[arg-type]
            user_id="sensor9",
            password="hunter2",
            ip="10.0.0.9",
            topic_rw="sensors/sensor9/#",
            topic_r="alerts/+",
            ca_passphrase="correct-horse",
            key_material=mat,
        )
        self.assertTrue(result.ok)
        self.assertEqual(result.status, "ok")
        self.assertIn("user sensor9\n", ssh.read_text(ACL))
        self.assertIn("sensor9:$7$1000$", ssh.read_text(PW))
        self.assertNotIn("hunter2", ssh.read_text(PW))
        self.assertIsNotNone(result.cert_bundle)
        self.assertTrue(any(k.startswith(ACL + ".bak.") for k in ssh.files))
        self.assertTrue(any("systemctl reload mosquitto" in c for c in ssh.commands))
        self.assertFalse(any("docker" in c for c in ssh.commands))
        self.assertFalse(any("haproxy" in c for c in ssh.commands))
        self.assertFalse(any("mosquitto_passwd" in c for c in ssh.commands))
        self.assertTrue(any("iotgw-ca-pass-" in p for p in ssh.unlinked))
        self.assertTrue(any("iotgw-csr-" in p for p in ssh.unlinked))
        self.assertEqual(result.details.get("mosquitto"), "reload")

    def test_register_upserts_existing_user(self) -> None:
        ssh = FakeSSH(_base_files())
        mat = generate_client_key_and_csr("sensor1")
        signed = local_self_sign_for_tests(mat)
        ssh._run_handler = _register_ok_handler(ssh, signed.client_crt_pem)

        result = register_device(
            ssh,  # type: ignore[arg-type]
            user_id="sensor1",
            password="newpass",
            ip="10.0.0.1",
            topic_rw="sensors/sensor1/v2/#",
            ca_passphrase="secret",
            key_material=mat,
        )
        self.assertTrue(result.ok)
        text = ssh.read_text(ACL)
        self.assertEqual(text.count("user sensor1\n"), 1)
        self.assertIn("topic readwrite sensors/sensor1/v2/#\n", text)
        self.assertNotIn("topic readwrite sensors/sensor1/#\n", text)

    def test_register_rejects_reserved(self) -> None:
        ssh = FakeSSH(_base_files())
        result = register_device(
            ssh,  # type: ignore[arg-type]
            user_id="nodered",
            password="x",
            ip="10.0.0.1",
            ca_passphrase="secret",
        )
        self.assertFalse(result.ok)
        self.assertIn("reserved", result.message)

    def test_register_compensates_on_password_write_failure(self) -> None:
        ssh = FakeSSH(_base_files())
        original_acl = ssh.read_text(ACL)
        original_pw = ssh.read_text(PW)

        def boom_write(path: str, content: str, *, mode: int = 0o644) -> None:
            if path == PW:
                raise RuntimeError("disk full")
            FakeSSH.write_text(ssh, path, content, mode=mode)

        ssh.write_text = boom_write  # type: ignore[method-assign]
        result = register_device(
            ssh,  # type: ignore[arg-type]
            user_id="sensor9",
            password="x",
            ip="10.0.0.9",
            topic_rw="sensors/sensor9/#",
            ca_passphrase="secret",
        )
        self.assertFalse(result.ok)
        self.assertEqual(ssh.read_text(ACL), original_acl)
        self.assertEqual(ssh.read_text(PW), original_pw)

    def test_register_mosquitto_reload_degraded_no_rollback(self) -> None:
        ssh = FakeSSH(_base_files())
        mat = generate_client_key_and_csr("sensor9")
        signed = local_self_sign_for_tests(mat)

        def run_handler(cmd: str) -> CommandResult:
            if "openssl x509 -req" in cmd:
                out_path = cmd.split()[cmd.split().index("-out") + 1].strip("'")
                ssh.files[out_path] = signed.client_crt_pem
                return CommandResult(argv=cmd, exit_code=0, stdout="", stderr="")
            if "systemctl reload mosquitto" in cmd:
                return CommandResult(argv=cmd, exit_code=1, stdout="", stderr="no")
            if "systemctl restart mosquitto" in cmd:
                return CommandResult(argv=cmd, exit_code=1, stdout="", stderr="boom")
            return CommandResult(argv=cmd, exit_code=0, stdout="", stderr="")

        ssh._run_handler = run_handler
        result = register_device(
            ssh,  # type: ignore[arg-type]
            user_id="sensor9",
            password="x",
            ip="10.0.0.9",
            topic_rw="sensors/sensor9/#",
            ca_passphrase="secret",
            key_material=mat,
        )
        self.assertTrue(result.ok)
        self.assertEqual(result.status, "degraded")
        self.assertIn("user sensor9\n", ssh.read_text(ACL))
        self.assertIn("sensor9:$7$", ssh.read_text(PW))
        self.assertIn("mosquitto reload failed", result.message)

    def test_register_reload_falls_back_to_restart(self) -> None:
        ssh = FakeSSH(_base_files())
        mat = generate_client_key_and_csr("sensor9")
        signed = local_self_sign_for_tests(mat)

        def run_handler(cmd: str) -> CommandResult:
            if "openssl x509 -req" in cmd:
                out_path = cmd.split()[cmd.split().index("-out") + 1].strip("'")
                ssh.files[out_path] = signed.client_crt_pem
                return CommandResult(argv=cmd, exit_code=0, stdout="", stderr="")
            if "systemctl reload mosquitto" in cmd:
                return CommandResult(argv=cmd, exit_code=1, stdout="", stderr="no")
            return CommandResult(argv=cmd, exit_code=0, stdout="", stderr="")

        ssh._run_handler = run_handler
        result = register_device(
            ssh,  # type: ignore[arg-type]
            user_id="sensor9",
            password="x",
            ip="10.0.0.9",
            topic_rw="sensors/sensor9/#",
            ca_passphrase="secret",
            key_material=mat,
        )
        self.assertTrue(result.ok)
        self.assertEqual(result.status, "ok")
        self.assertEqual(result.details.get("mosquitto"), "restart")
        self.assertTrue(any("systemctl restart mosquitto" in c for c in ssh.commands))


class TestUpdateAcl(unittest.TestCase):
    def test_update_acl(self) -> None:
        ssh = FakeSSH(_base_files())
        result = update_acl(
            ssh,  # type: ignore[arg-type]
            user_id="sensor1",
            add_rw="sensors/sensor1/new",
            delete_r="alerts/+",
        )
        self.assertTrue(result.ok)
        text = ssh.read_text(ACL)
        self.assertIn("topic readwrite sensors/sensor1/new\n", text)
        self.assertNotIn("topic read alerts/+\n", text)
        self.assertTrue(any("systemctl reload mosquitto" in c for c in ssh.commands))


class TestUnregister(unittest.TestCase):
    def test_unregister_without_ip(self) -> None:
        ssh = FakeSSH(_base_files())
        result = unregister_device(ssh, user_id="sensor1")  # type: ignore[arg-type]
        self.assertTrue(result.ok)
        self.assertNotIn("user sensor1\n", ssh.read_text(ACL))
        self.assertNotIn("sensor1:", ssh.read_text(PW))

    def test_unregister_with_ip_flag_is_noop_for_files(self) -> None:
        ssh = FakeSSH(_base_files())
        result = unregister_device(
            ssh,  # type: ignore[arg-type]
            user_id="sensor1",
            ip="10.0.0.1",
            remove_ip=True,
        )
        self.assertTrue(result.ok)
        self.assertEqual(result.details.get("removed_ip"), "10.0.0.1")
        self.assertNotIn("user sensor1\n", ssh.read_text(ACL))
        self.assertFalse(any("haproxy" in c for c in ssh.commands))


class TestClearLogs(unittest.TestCase):
    def test_clear_logs(self) -> None:
        files = _base_files()
        log_paths = [
            f"{DATA}/mosquitto/log/mosquitto.log",
            f"{DATA}/logs/sensor_data.log",
        ]
        for p in log_paths:
            files[p] = "old log data\n"
        ssh = FakeSSH(files)
        result = clear_logs(ssh)  # type: ignore[arg-type]
        self.assertTrue(result.ok)
        self.assertEqual(len(result.details["truncated"]), 2)
        for p in log_paths:
            self.assertEqual(ssh.read_text(p), "")


class TestValidation(unittest.TestCase):
    def test_bad_ip(self) -> None:
        ssh = FakeSSH(_base_files())
        result = register_device(
            ssh,  # type: ignore[arg-type]
            user_id="sensor9",
            password="x",
            ip="not-an-ip",
            ca_passphrase="secret",
        )
        self.assertFalse(result.ok)


if __name__ == "__main__":
    unittest.main()
