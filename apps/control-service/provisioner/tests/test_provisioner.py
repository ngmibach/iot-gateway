"""Unit tests for SSH provisioner with a fake SSH session (agent-only)."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from provisioner.provision import (
    DEFAULT_INSTALL_ROOT,
    ProvisionConfig,
    ProvisionError,
    _parse_df_available_bytes,
    latest_backup_path,
    list_remote_backups,
    provision,
    rollback_install,
)
from provisioner.ssh import CommandResult


class FakeSSH:
    """In-memory SSHSession stand-in."""

    def __init__(self) -> None:
        self.commands: list[str] = []
        self.uploads: list[tuple[str, int]] = []
        self.trees: list[tuple[str, str]] = []
        self.files: dict[str, bytes] = {}
        self._handlers: list[tuple] = []
        self.upload_tree_error: Exception | None = None
        self.closed = False

    def when(self, substr: str, result: CommandResult | None = None, *, contains: bool = True):
        if result is None:
            result = CommandResult(0, "OK\n", "")
        self._handlers.append((substr, contains, result))
        return self

    def run(
        self,
        command: str,
        *,
        timeout: float = 120.0,
        stdin: str | None = None,
    ) -> CommandResult:
        self.commands.append(command)
        if stdin is not None:
            self.stdins = getattr(self, "stdins", [])
            self.stdins.append(stdin)
        for substr, contains, result in reversed(self._handlers):
            hit = (substr in command) if contains else (command == substr)
            if hit:
                return result
        return CommandResult(0, "", "")

    def upload_file(self, local_path: Path, remote_path: str, *, mode: int = 0o644) -> None:
        self.uploads.append((remote_path, mode))
        self.files[remote_path] = Path(local_path).read_bytes()

    def upload_tree(self, local_dir: Path, remote_dir: str) -> None:
        if self.upload_tree_error is not None:
            raise self.upload_tree_error
        self.trees.append((str(local_dir), remote_dir))

    def close(self) -> None:
        self.closed = True


def _ok_ssh(*, free_k: int = 5_000_000) -> FakeSSH:
    ssh = FakeSSH()
    df_line = f"/dev/sda1 20000000 1000000 {free_k} 5% /opt\n"
    ssh.when("df -Pk", CommandResult(0, df_line, ""))
    ssh.when("printf '%s:%s", CommandResult(0, "admin:admin\n", ""))
    return ssh


class ParseDfTests(unittest.TestCase):
    def test_parse_df(self) -> None:
        line = "/dev/root 31249408 10485760 18612224 37% /"
        self.assertEqual(_parse_df_available_bytes(line), 18612224 * 1024)

    def test_parse_df_bad(self) -> None:
        self.assertIsNone(_parse_df_available_bytes(""))
        self.assertIsNone(_parse_df_available_bytes("nope"))


class BackupPathTests(unittest.TestCase):
    def test_latest_backup_scoped_to_install_root(self) -> None:
        paths = [
            "/opt/iot-gateway-agent.bak-100",
            "/opt/iot-gateway-agent.bak-250",
            "/opt/other.bak-999",
            "/opt/iot-gateway-agent.bak-200",
        ]
        self.assertEqual(
            latest_backup_path(paths, DEFAULT_INSTALL_ROOT),
            "/opt/iot-gateway-agent.bak-250",
        )
        self.assertIsNone(latest_backup_path(paths, "/opt/missing"))

    def test_list_remote_backups_uses_find_name(self) -> None:
        ssh = FakeSSH()
        ssh.when(
            "find ",
            CommandResult(
                0,
                "/opt/iot-gateway-agent.bak-100\n/opt/iot-gateway-agent.bak-250\n"
                "/opt/other.bak-999\n",
                "",
            ),
        )
        found = list_remote_backups(ssh, DEFAULT_INSTALL_ROOT)
        self.assertEqual(
            found,
            [
                "/opt/iot-gateway-agent.bak-100",
                "/opt/iot-gateway-agent.bak-250",
                "/opt/other.bak-999",
            ],
        )
        cmd = ssh.commands[0]
        self.assertIn("find ", cmd)
        self.assertIn("-name ", cmd)
        self.assertIn("iot-gateway-agent.bak-*", cmd)
        self.assertNotIn("/opt/iot-gateway-agent.bak-*", cmd)
        self.assertTrue(
            latest_backup_path(found, DEFAULT_INSTALL_ROOT)
            == "/opt/iot-gateway-agent.bak-250"
        )

    def test_rollback_discovers_newest_backup(self) -> None:
        ssh = FakeSSH()
        ssh.when(
            "find ",
            CommandResult(
                0,
                "/opt/iot-gateway-agent.bak-100\n/opt/iot-gateway-agent.bak-250\n",
                "",
            ),
        )
        ssh.when("rm -rf", CommandResult(0, "", ""))
        ssh.when("mv ", CommandResult(0, "", ""))
        restored = rollback_install(ssh, DEFAULT_INSTALL_ROOT, backup_path=None)
        self.assertEqual(restored, "/opt/iot-gateway-agent.bak-250")
        self.assertTrue(
            any(
                c.startswith("mv ") and "/opt/iot-gateway-agent.bak-250" in c
                for c in ssh.commands
            )
        )


class ProvisionFlowTests(unittest.TestCase):
    def setUp(self) -> None:
        self.repo = Path(__file__).resolve().parents[4]

    def _config(self, **kwargs) -> ProvisionConfig:
        base = dict(
            gateway_ip="192.168.1.50",
            monitoring_ip="192.168.1.10",
            gateway_src=self.repo / "gateway",
            repo_root=self.repo,
            sudo_password="test-sudo-secret",
            ca_passphrase="test-ca-passphrase-not-admin",
        )
        base.update(kwargs)
        return ProvisionConfig(**base)

    def test_default_install_root_is_agent(self) -> None:
        self.assertEqual(DEFAULT_INSTALL_ROOT, "/opt/iot-gateway-agent")

    def test_uninstall_monolithic_agent(self) -> None:
        from provisioner.agent_install import uninstall_monolithic_agent

        ssh = _ok_ssh()
        ssh.when("sudo -S", CommandResult(0, "", ""))
        notes = uninstall_monolithic_agent(ssh, sudo_password="test-sudo-secret")
        self.assertTrue(any("stopped" in n for n in notes))
        self.assertTrue(any("removed" in n for n in notes))
        self.assertTrue(
            any("fake" in n.lower() and "torn" in n.lower() for n in notes)
            or any("fake sensor" in n.lower() for n in notes),
            notes,
        )
        self.assertFalse(any("test-sudo-secret" in c for c in ssh.commands))
        self.assertTrue(any("iot-gateway-agent" in c for c in ssh.commands))
        self.assertTrue(any("/opt/iot-gateway-agent" in c for c in ssh.commands))
        self.assertTrue(any("iotgw-fake@" in c for c in ssh.commands))
        self.assertTrue(any("iotgw-fake@.service" in c for c in ssh.commands))
        self.assertTrue(any("ip netns" in c for c in ssh.commands))

    def test_sudo_run_wraps_compound_command_in_sh_c(self) -> None:
        from provisioner.agent_install import sudo_run

        ssh = FakeSSH()
        ssh.when("sudo -S", CommandResult(0, "", ""))
        result = sudo_run(
            ssh,
            "mkdir -p /var/lib/iot-gateway-agent && "
            "mv /tmp/iotgw-agent.env /etc/iot-gateway-agent.env",
            sudo_password="secret",
        )
        self.assertTrue(result.ok)
        self.assertEqual(len(ssh.commands), 1)
        cmd = ssh.commands[0]
        self.assertIn("sudo -S -p '' -- sh -c ", cmd)
        self.assertIn("/etc/iot-gateway-agent.env", cmd)
        self.assertNotRegex(cmd, r"-- mkdir -p .* && mv ")
        self.assertFalse(any("secret" in c for c in ssh.commands))
        self.assertTrue(any("secret" in s for s in getattr(ssh, "stdins", [])))

    def test_upload_agent_tree_chowns_login_user_not_root(self) -> None:
        from provisioner import agent_install

        ssh = FakeSSH()
        ssh.when("printf '%s:%s", CommandResult(0, "admin:admin\n", ""))
        ssh.when("sudo -S", CommandResult(0, "", ""))
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            pkg = root / "iot_gateway_agent"
            pkg.mkdir()
            (pkg / "__init__.py").write_text("#\n", encoding="utf-8")
            (root / "requirements.txt").write_text("x==1\n", encoding="utf-8")
            agent_install._upload_agent_tree(
                ssh,
                root,
                "/opt/iot-gateway-agent",
                sudo_password="secret",
            )
        sudo_cmds = [c for c in ssh.commands if "sudo -S" in c]
        self.assertTrue(sudo_cmds)
        prepare = sudo_cmds[0]
        self.assertIn("chown -R admin:admin", prepare)
        self.assertIn("rm -rf /opt/iot-gateway-agent/iot_gateway_agent", prepare)
        self.assertNotIn("$(id -un)", prepare)
        self.assertEqual(ssh.trees[0][1], "/opt/iot-gateway-agent/iot_gateway_agent")

    def test_mosquitto_present_accepts_usr_sbin(self) -> None:
        from provisioner.agent_install import _mosquitto_present

        ssh = FakeSSH()
        ssh.when("/usr/sbin/mosquitto", CommandResult(0, "OK\n", ""))
        self.assertTrue(_mosquitto_present(ssh))

    def test_mosquitto_present_ignores_exit_when_stdout_ok(self) -> None:
        from provisioner.agent_install import _mosquitto_present

        ssh = FakeSSH()
        ssh.when(
            "test -x /usr/sbin/mosquitto",
            CommandResult(1, "OK\n", ""),
        )
        self.assertTrue(_mosquitto_present(ssh))

    def test_mosquitto_present_false_when_absent(self) -> None:
        from provisioner.agent_install import _mosquitto_present

        ssh = FakeSSH()
        ssh.when("mosquitto", CommandResult(0, "", ""))
        self.assertFalse(_mosquitto_present(ssh))

    def test_configure_system_mosquitto_writes_mqtts_conf_d(self) -> None:
        from provisioner.agent_install import (
            DEFAULT_AGENT_DATA,
            MQTT_TLS_PORT,
            _MOSQUITTO_CONF_D,
            _mqtts_conf_body,
            configure_system_mosquitto,
        )

        body = _mqtts_conf_body(data_dir=DEFAULT_AGENT_DATA)
        self.assertIn(f"listener {MQTT_TLS_PORT}", body)
        self.assertIn("require_certificate true", body)
        self.assertIn("cafile", body)
        self.assertNotIn("listener 1883", body)

        ssh = FakeSSH()
        ssh.when("sudo -S", CommandResult(0, "", ""))
        ssh.when("rm -f", CommandResult(0, "", ""))
        note, decrypt_pw = configure_system_mosquitto(ssh, sudo_password="secret")
        self.assertIn("MQTTS", note)
        self.assertIsNone(decrypt_pw)
        self.assertTrue(any(_MOSQUITTO_CONF_D in c for c in ssh.commands))
        self.assertTrue(
            any(DEFAULT_AGENT_DATA + "/mosquitto" in c for c in ssh.commands)
        )
        conf_bytes = b""
        for path, data in ssh.files.items():
            if path.endswith(".conf") or "mosquitto-agent.conf" in path:
                conf_bytes = data
                break
        if not conf_bytes:
            # Uploaded temp path may vary; scan all uploads.
            for data in ssh.files.values():
                if b"listener" in data and b"8883" in data:
                    conf_bytes = data
                    break
        self.assertIn(b"listener 8883", conf_bytes)
        self.assertIn(b"require_certificate true", conf_bytes)
        self.assertNotIn(b"listener 1883", conf_bytes)
        conf_uploads = [p for p, _ in ssh.uploads if p.endswith(".conf") or "mosquitto" in p]
        self.assertTrue(conf_uploads)
        sudo_cmds = [c for c in ssh.commands if "sudo -S" in c]
        self.assertTrue(sudo_cmds)
        self.assertIn("systemctl enable --now mosquitto", sudo_cmds[0])
        self.assertIn("/etc/mosquitto/conf.d", sudo_cmds[0])
        self.assertFalse(any("secret" in c for c in ssh.commands))

    def test_ensure_kafka_layout_seeds_catalog(self) -> None:
        from provisioner.agent_install import (
            DEFAULT_AGENT_DATA,
            ensure_kafka_layout,
        )

        ssh = FakeSSH()
        ssh.when("sudo -S", CommandResult(0, "", ""))
        ssh.when("rm -f", CommandResult(0, "", ""))
        note = ensure_kafka_layout(ssh, sudo_password="secret")
        self.assertIn("kafka topic catalog ready", note)
        self.assertTrue(
            any(DEFAULT_AGENT_DATA + "/kafka" in c for c in ssh.commands)
        )
        self.assertTrue(
            any("topics.json" in c for c in ssh.commands)
        )
        self.assertFalse(any("secret" in c for c in ssh.commands))

    def test_kafka_server_properties_lan_advertise(self) -> None:
        from provisioner.kafka_install import _server_properties

        props = _server_properties(
            data_dir="/var/lib/iot-gateway-agent",
            advertise_host="192.168.1.50",
        )
        self.assertIn(
            "listeners=PLAINTEXT://0.0.0.0:9092,CONTROLLER://127.0.0.1:9093",
            props,
        )
        self.assertIn(
            "advertised.listeners=PLAINTEXT://192.168.1.50:9092",
            props,
        )
        self.assertNotIn("PLAINTEXT://127.0.0.1:9092,CONTROLLER", props)

    def test_kafka_server_properties_fallback_loopback(self) -> None:
        from provisioner.kafka_install import _server_properties

        props = _server_properties(
            data_dir="/var/lib/iot-gateway-agent",
            advertise_host="",
        )
        self.assertIn("advertised.listeners=PLAINTEXT://127.0.0.1:9092", props)
        self.assertIn("listeners=PLAINTEXT://0.0.0.0:9092,", props)

    def test_agent_backend_no_docker(self) -> None:
        ssh = _ok_ssh()
        ssh.when("command -v mosquitto", CommandResult(0, "OK\n", ""))
        ssh.when("import ensurepip", CommandResult(0, "OK\n", ""))
        ssh.when("command -v python3", CommandResult(0, "/usr/bin/python3\n", ""))
        ssh.when("python3 -m venv", CommandResult(0, "", ""))
        ssh.when("pip install", CommandResult(0, "", ""))
        ssh.when("systemctl", CommandResult(0, "", ""))
        ssh.when(
            "curl -fsS http://127.0.0.1:9139/v1/health",
            CommandResult(0, '{"status":"ok"}', ""),
        )
        ssh.when("printf '%s:%s", CommandResult(0, "admin:admin\n", ""))
        # TLS bootstrap sudo scripts echo markers; generic sudo stays empty.
        ssh.when("DECRYPT_OK", CommandResult(0, "DECRYPT_OK\n", ""))
        ssh.when("CA_CREATED", CommandResult(0, "CA_EXISTS\n", ""))
        ssh.when("SERVER_CREATED", CommandResult(0, "SERVER_EXISTS\n", ""))
        ssh.when("openssl", CommandResult(0, "CA_EXISTS\nSERVER_EXISTS\nDECRYPT_OK\n", ""))
        ssh.when("sudo -S", CommandResult(0, "CA_EXISTS\nSERVER_EXISTS\nDECRYPT_OK\n", ""))
        result = provision(ssh, self._config())
        self.assertEqual(result.backend, "agent")
        self.assertEqual(result.install_root, DEFAULT_INSTALL_ROOT)
        self.assertTrue(result.agent_installed)
        self.assertTrue(any("no Docker" in n for n in result.notes))
        self.assertTrue(any("8883" in (result.probes.get("mqtts") or "") for _ in [0]))
        self.assertEqual(result.probes.get("mqtts"), "192.168.1.50:8883")
        self.assertFalse(any("docker info" in c for c in ssh.commands))
        self.assertFalse(any("docker compose" in c for c in ssh.commands))
        self.assertFalse(any("test-sudo-secret" in c for c in ssh.commands))
        self.assertFalse(any("test-ca-passphrase" in c for c in ssh.commands))

    def test_agent_backend_apt_uses_sudo_stdin(self) -> None:
        ssh = _ok_ssh()
        calls = {"n": 0}

        def _run(command, *, timeout=120.0, stdin=None):
            ssh.commands.append(command)
            if stdin is not None:
                ssh.stdins = getattr(ssh, "stdins", [])
                ssh.stdins.append(stdin)
            if "command -v mosquitto" in command or "test -x /usr/sbin/mosquitto" in command:
                calls["n"] += 1
                if calls["n"] == 1:
                    return CommandResult(1, "", "missing")
                return CommandResult(0, "OK\n", "")
            if "import ensurepip" in command:
                return CommandResult(1, "", "")
            if "curl -fsS http://127.0.0.1:9139" in command:
                return CommandResult(0, '{"status": "ok"}', "")
            if "printf '%s:%s" in command:
                return CommandResult(0, "admin:admin\n", "")
            if "sudo -S" in command:
                # Mimic TLS bootstrap markers from ensure_* scripts.
                return CommandResult(
                    0, "CA_EXISTS\nSERVER_EXISTS\nDECRYPT_OK\n", ""
                )
            if "command -v python3" in command:
                return CommandResult(0, "/usr/bin/python3\n", "")
            if "df -Pk" in command:
                return CommandResult(0, "/dev/sda1 20000000 1000000 5000000 5% /opt\n", "")
            return CommandResult(0, "", "")

        ssh.run = _run  # type: ignore[method-assign]
        result = provision(ssh, self._config(sudo_password="s3cret-sudo"))
        self.assertEqual(result.backend, "agent")
        self.assertTrue(any("installed via apt" in n for n in result.notes))
        self.assertTrue(any("sudo -S" in c for c in ssh.commands))
        self.assertFalse(any("s3cret-sudo" in c for c in ssh.commands))
        self.assertTrue(any("s3cret-sudo" in s for s in getattr(ssh, "stdins", [])))
        apt_cmds = [c for c in ssh.commands if "apt-get" in c]
        self.assertTrue(apt_cmds, "expected apt-get under sudo")
        for c in apt_cmds:
            self.assertIn("env DEBIAN_FRONTEND=noninteractive", c)
            self.assertIn("sh -c ", c)
            self.assertNotIn("-- DEBIAN_FRONTEND=", c)

    def test_agent_backend_requires_sudo_password(self) -> None:
        ssh = _ok_ssh()
        with self.assertRaises(ProvisionError) as ctx:
            provision(ssh, self._config(sudo_password=""))
        self.assertIn("sudo password", str(ctx.exception).lower())

    def test_agent_backend_requires_ca_passphrase(self) -> None:
        ssh = _ok_ssh()
        ssh.when("sudo -S", CommandResult(0, "", ""))
        with self.assertRaises(ProvisionError) as ctx:
            provision(ssh, self._config(ca_passphrase=""))
        self.assertIn("ca passphrase", str(ctx.exception).lower())

    def test_disk_preflight_aborts(self) -> None:
        ssh = _ok_ssh(free_k=100)
        with self.assertRaises(ProvisionError) as ctx:
            provision(ssh, self._config())
        self.assertIn("insufficient disk", str(ctx.exception))
        self.assertEqual(ssh.trees, [])

    def test_missing_agent_src_is_provision_error(self) -> None:
        ssh = _ok_ssh()
        with self.assertRaises(ProvisionError) as ctx:
            provision(ssh, self._config(gateway_src=Path("/nonexistent-gateway-src")))
        self.assertIn("missing", str(ctx.exception).lower())

    def test_rollback_install_restores_backup(self) -> None:
        ssh = FakeSSH()
        ssh.when("rm -rf", CommandResult(0, "", ""))
        ssh.when("mv ", CommandResult(0, "", ""))
        rollback_install(
            ssh, DEFAULT_INSTALL_ROOT, "/opt/iot-gateway-agent.bak-1"
        )
        self.assertFalse(any("docker" in c for c in ssh.commands))
        self.assertTrue(any("rm -rf" in c for c in ssh.commands))
        self.assertTrue(
            any(
                c.startswith("mv ")
                and "/opt/iot-gateway-agent.bak-1" in c
                and DEFAULT_INSTALL_ROOT in c
                for c in ssh.commands
            )
        )


if __name__ == "__main__":
    unittest.main()
