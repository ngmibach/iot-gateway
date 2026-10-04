"""Playbook unit tests with mocked SSH."""

from __future__ import annotations

import unittest

from actions.csr import generate_client_key_and_csr
from actions.playbooks import (
    clear_logs,
    register_device,
    unregister_device,
    update_acl,
    update_allowlist_ips,
)
from actions.ssh import CommandResult
from tests.cert_helpers import local_self_sign_for_tests
from tests.fake_ssh import FakeSSH

ROOT = "/opt/iot-gateway"
ACL = f"{ROOT}/mosquitto/config/acl"
PW = f"{ROOT}/mosquitto/config/passwords"
IPS = f"{ROOT}/haproxy/allowed-ips.txt"
CA = f"{ROOT}/certs/ca.crt"

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

BASE_IPS = "10.0.0.1\n172.22.0.0/16\n"


def _base_files() -> dict[str, str]:
    return {
        ACL: BASE_ACL,
        PW: BASE_PW,
        IPS: BASE_IPS,
        CA: "-----BEGIN CERTIFICATE-----\nCA\n-----END CERTIFICATE-----\n",
        f"{ROOT}/certs/ca.key": "-----BEGIN ENCRYPTED PRIVATE KEY-----\nX\n-----END ENCRYPTED PRIVATE KEY-----\n",
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
        self.assertIn("10.0.0.9", ssh.read_text(IPS))
        self.assertIsNotNone(result.cert_bundle)
        self.assertTrue(any(k.startswith(ACL + ".bak.") for k in ssh.files))
        self.assertTrue(any("restart mosquitto" in c for c in ssh.commands))
        self.assertTrue(any("docker kill -s HUP" in c for c in ssh.commands))
        self.assertFalse(any("mosquitto_passwd" in c for c in ssh.commands))
        self.assertTrue(any("iotgw-ca-pass-" in p for p in ssh.unlinked))
        self.assertTrue(any("iotgw-csr-" in p for p in ssh.unlinked))

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

    def test_register_compensates_on_allowlist_failure(self) -> None:
        ssh = FakeSSH(_base_files())
        original_acl = ssh.read_text(ACL)
        original_pw = ssh.read_text(PW)

        def boom_write(path: str, content: str, *, mode: int = 0o644) -> None:
            if path == IPS:
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

    def test_register_mosquitto_restart_degraded_no_rollback(self) -> None:
        ssh = FakeSSH(_base_files())
        mat = generate_client_key_and_csr("sensor9")
        signed = local_self_sign_for_tests(mat)

        def run_handler(cmd: str) -> CommandResult:
            if "openssl x509 -req" in cmd:
                out_path = cmd.split()[cmd.split().index("-out") + 1].strip("'")
                ssh.files[out_path] = signed.client_crt_pem
                return CommandResult(argv=cmd, exit_code=0, stdout="", stderr="")
            if "restart mosquitto" in cmd:
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
        self.assertIn("10.0.0.9", ssh.read_text(IPS))

    def test_register_haproxy_failure_degraded_no_mosquitto_rollback(self) -> None:
        ssh = FakeSSH(_base_files())
        mat = generate_client_key_and_csr("sensor9")
        signed = local_self_sign_for_tests(mat)

        def run_handler(cmd: str) -> CommandResult:
            if "openssl x509 -req" in cmd:
                out_path = cmd.split()[cmd.split().index("-out") + 1].strip("'")
                ssh.files[out_path] = signed.client_crt_pem
                return CommandResult(argv=cmd, exit_code=0, stdout="", stderr="")
            if "docker kill -s HUP" in cmd:
                return CommandResult(argv=cmd, exit_code=1, stdout="", stderr="no")
            if "restart haproxy" in cmd:
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
        self.assertEqual(result.status, "degraded")
        self.assertIn("allow-list may be stale", result.message)
        self.assertIn("user sensor9\n", ssh.read_text(ACL))


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
        self.assertTrue(any("restart mosquitto" in c for c in ssh.commands))


class TestAllowlist(unittest.TestCase):
    def test_add_and_remove(self) -> None:
        ssh = FakeSSH(_base_files())
        result = update_allowlist_ips(
            ssh,  # type: ignore[arg-type]
            add_ips="10.0.0.5,10.0.0.1",
            remove_ips=["172.22.0.0/16"],
        )
        self.assertTrue(result.ok)
        text = ssh.read_text(IPS)
        self.assertIn("10.0.0.5", text)
        self.assertIn("10.0.0.1", text)
        self.assertNotIn("172.22.0.0/16", text)

    def test_remove_all(self) -> None:
        ssh = FakeSSH(_base_files())
        result = update_allowlist_ips(ssh, remove_all=True)  # type: ignore[arg-type]
        self.assertTrue(result.ok)
        self.assertEqual(ssh.read_text(IPS), "")

    def test_hup_fallback_to_restart(self) -> None:
        ssh = FakeSSH(_base_files())

        def run_handler(cmd: str) -> CommandResult:
            if "docker kill -s HUP" in cmd:
                return CommandResult(argv=cmd, exit_code=1, stdout="", stderr="no")
            return CommandResult(argv=cmd, exit_code=0, stdout="", stderr="")

        ssh._run_handler = run_handler
        result = update_allowlist_ips(ssh, add_ips=["10.0.0.8"])  # type: ignore[arg-type]
        self.assertTrue(result.ok)
        self.assertEqual(result.details.get("haproxy"), "restart")
        self.assertTrue(any("restart haproxy" in c for c in ssh.commands))
        self.assertFalse(any("down -v" in c for c in ssh.commands))


class TestUnregister(unittest.TestCase):
    def test_unregister_without_ip(self) -> None:
        ssh = FakeSSH(_base_files())
        result = unregister_device(ssh, user_id="sensor1")  # type: ignore[arg-type]
        self.assertTrue(result.ok)
        self.assertNotIn("user sensor1\n", ssh.read_text(ACL))
        self.assertNotIn("sensor1:", ssh.read_text(PW))
        self.assertIn("10.0.0.1", ssh.read_text(IPS))

    def test_unregister_with_ip(self) -> None:
        ssh = FakeSSH(_base_files())
        result = unregister_device(
            ssh,  # type: ignore[arg-type]
            user_id="sensor1",
            ip="10.0.0.1",
            remove_ip=True,
        )
        self.assertTrue(result.ok)
        self.assertNotIn("10.0.0.1", ssh.read_text(IPS))

    def test_unregister_haproxy_failure_no_acl_restore(self) -> None:
        ssh = FakeSSH(_base_files())

        def run_handler(cmd: str) -> CommandResult:
            if "restart mosquitto" in cmd:
                return CommandResult(argv=cmd, exit_code=0, stdout="", stderr="")
            if "docker kill -s HUP" in cmd or "restart haproxy" in cmd:
                return CommandResult(argv=cmd, exit_code=1, stdout="", stderr="fail")
            return CommandResult(argv=cmd, exit_code=0, stdout="", stderr="")

        ssh._run_handler = run_handler
        result = unregister_device(
            ssh,  # type: ignore[arg-type]
            user_id="sensor1",
            ip="10.0.0.1",
            remove_ip=True,
        )
        self.assertTrue(result.ok)
        self.assertEqual(result.status, "degraded")
        self.assertNotIn("user sensor1\n", ssh.read_text(ACL))
        self.assertNotIn("sensor1:", ssh.read_text(PW))
        # IP file change kept (stale allow-list vs haproxy)
        self.assertNotIn("10.0.0.1", ssh.read_text(IPS))


class TestClearLogs(unittest.TestCase):
    def test_clear_logs(self) -> None:
        files = _base_files()
        log_paths = [
            f"{ROOT}/mosquitto/log/mosquitto.log",
            f"{ROOT}/nodered/data/logs/sensor_data.log",
            f"{ROOT}/haproxy/logs/haproxy.log",
            f"{ROOT}/logs/gateway-state.log",
            f"{ROOT}/logs/ids-alerts.log",
        ]
        for p in log_paths:
            files[p] = "old log data\n"
        ssh = FakeSSH(files)
        result = clear_logs(ssh)  # type: ignore[arg-type]
        self.assertTrue(result.ok)
        self.assertEqual(len(result.details["truncated"]), 5)
        for p in log_paths:
            self.assertEqual(ssh.read_text(p), "")


class TestValidation(unittest.TestCase):
    def test_bad_ip(self) -> None:
        ssh = FakeSSH(_base_files())
        result = update_allowlist_ips(ssh, add_ips=["not-an-ip"])  # type: ignore[arg-type]
        self.assertFalse(result.ok)


if __name__ == "__main__":
    unittest.main()
