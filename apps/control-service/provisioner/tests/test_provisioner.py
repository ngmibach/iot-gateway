"""Unit tests for SSH provisioner with a fake SSH session."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from provisioner.bundle import stage_gateway_bundle
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

    def run(self, command: str, *, timeout: float = 120.0) -> CommandResult:
        self.commands.append(command)
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


def _ok_ssh(*, exists: bool = False, free_k: int = 5_000_000) -> FakeSSH:
    ssh = FakeSSH()
    ssh.when("docker info", CommandResult(0, "OK\n", ""))
    df_line = f"/dev/sda1 20000000 1000000 {free_k} 5% /opt\n"
    ssh.when("df -Pk", CommandResult(0, df_line, ""))
    # shlex.quote leaves safe paths unquoted.
    exists_substr = f"if [ -e {DEFAULT_INSTALL_ROOT} ]"
    if exists:
        ssh.when(exists_substr, CommandResult(0, "EXISTS\n", ""))
    else:
        ssh.when(exists_substr, CommandResult(0, "", ""))
    ssh.when("docker compose", CommandResult(0, "started\n", ""))
    ssh.when("curl -fsS", CommandResult(0, "ready\n__LOKI_OK__\n", ""))
    ssh.when("test -f", CommandResult(0, "OK\n", ""))
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
            "/opt/iot-gateway.bak-100",
            "/opt/iot-gateway.bak-250",
            "/opt/other.bak-999",
            "/opt/iot-gateway.bak-200",
        ]
        self.assertEqual(
            latest_backup_path(paths, DEFAULT_INSTALL_ROOT),
            "/opt/iot-gateway.bak-250",
        )
        self.assertIsNone(latest_backup_path(paths, "/opt/missing"))

    def test_list_remote_backups_uses_find_name(self) -> None:
        ssh = FakeSSH()
        ssh.when(
            "find ",
            CommandResult(
                0,
                "/opt/iot-gateway.bak-100\n/opt/iot-gateway.bak-250\n/opt/other.bak-999\n",
                "",
            ),
        )
        found = list_remote_backups(ssh, DEFAULT_INSTALL_ROOT)
        self.assertEqual(
            found,
            [
                "/opt/iot-gateway.bak-100",
                "/opt/iot-gateway.bak-250",
                "/opt/other.bak-999",
            ],
        )
        cmd = ssh.commands[0]
        self.assertIn("find ", cmd)
        self.assertIn("-name ", cmd)
        # Glob must be its own quoted -name arg, not glued into a quoted path* pattern.
        self.assertIn("iot-gateway.bak-*", cmd)
        self.assertNotIn("/opt/iot-gateway.bak-*", cmd)
        self.assertTrue(
            latest_backup_path(found, DEFAULT_INSTALL_ROOT)
            == "/opt/iot-gateway.bak-250"
        )

    def test_rollback_discovers_newest_backup(self) -> None:
        ssh = FakeSSH()
        ssh.when(
            "find ",
            CommandResult(
                0,
                "/opt/iot-gateway.bak-100\n/opt/iot-gateway.bak-250\n",
                "",
            ),
        )
        ssh.when("docker compose", CommandResult(0, "", ""))
        ssh.when("rm -rf", CommandResult(0, "", ""))
        ssh.when("mv ", CommandResult(0, "", ""))
        restored = rollback_install(ssh, DEFAULT_INSTALL_ROOT, backup_path=None)
        self.assertEqual(restored, "/opt/iot-gateway.bak-250")
        self.assertTrue(
            any(
                c.startswith("mv ") and "/opt/iot-gateway.bak-250" in c
                for c in ssh.commands
            )
        )


class BundleStageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.repo = Path(__file__).resolve().parents[4]
        self.gateway = self.repo / "gateway"
        self.templates = self.repo / "deploy" / "templates"

    def test_renders_promtail_monitoring_ip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            staged = stage_gateway_bundle(
                self.gateway,
                Path(tmp) / "stage",
                values={"GATEWAY_IP": "10.0.0.5", "MONITORING_IP": "10.0.0.9"},
                template_dir=self.templates,
                repo_root=self.repo,
            )
            promtail = (
                staged / "promtail" / "config" / "promtail-config.yaml"
            ).read_text(encoding="utf-8")
            self.assertIn("http://10.0.0.9:3100/loki/api/v1/push", promtail)
            self.assertNotIn("{{MONITORING_IP}}", promtail)
            self.assertNotIn("172.17.0.1", promtail)
            self.assertTrue((staged / "docker-compose.yaml").is_file())
            self.assertFalse((staged / ".rendered-templates").exists())

    def test_missing_promtail_template_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tpl = Path(tmp) / "templates"
            tpl.mkdir()
            (tpl / "prometheus.yml").write_text("x: {{GATEWAY_IP}}\n", encoding="utf-8")
            with self.assertRaises((FileNotFoundError, ValueError)):
                stage_gateway_bundle(
                    self.gateway,
                    Path(tmp) / "stage",
                    values={"GATEWAY_IP": "10.0.0.5", "MONITORING_IP": "10.0.0.9"},
                    template_dir=tpl,
                    repo_root=self.repo,
                )


class ProvisionFlowTests(unittest.TestCase):
    def setUp(self) -> None:
        self.repo = Path(__file__).resolve().parents[4]
        self._interval_patch = mock.patch(
            "provisioner.provision.DEFAULT_PROBE_INTERVAL_S", 0
        )
        self._interval_patch.start()

    def tearDown(self) -> None:
        self._interval_patch.stop()

    def _config(self, **kwargs) -> ProvisionConfig:
        base = dict(
            gateway_ip="192.168.1.50",
            monitoring_ip="192.168.1.10",
            gateway_src=self.repo / "gateway",
            template_dir=self.repo / "deploy" / "templates",
            repo_root=self.repo,
            agent_mode="skip",
            probe_retries=1,
            loki_probe_retries=1,
            probe_interval_s=0,
        )
        base.update(kwargs)
        return ProvisionConfig(**base)

    def test_happy_path_skips_agent(self) -> None:
        ssh = _ok_ssh()
        with mock.patch(
            "provisioner.provision.probe_http",
            return_value=(True, "ok"),
        ):
            result = provision(ssh, self._config())
        self.assertEqual(result.install_root, DEFAULT_INSTALL_ROOT)
        self.assertFalse(result.agent_installed)
        self.assertEqual(len(ssh.trees), 1)
        self.assertEqual(ssh.trees[0][1], DEFAULT_INSTALL_ROOT)
        self.assertTrue(any("docker compose" in c and "up -d" in c for c in ssh.commands))
        self.assertIn("loki_from_gateway", result.probes)

    def test_disk_preflight_aborts(self) -> None:
        ssh = _ok_ssh(free_k=100)
        with self.assertRaises(ProvisionError) as ctx:
            provision(ssh, self._config())
        self.assertIn("insufficient disk", str(ctx.exception))
        self.assertEqual(ssh.trees, [])

    def test_docker_preflight_aborts(self) -> None:
        ssh = FakeSSH()
        ssh.when("docker info", CommandResult(1, "", "Cannot connect"))
        with self.assertRaises(ProvisionError) as ctx:
            provision(ssh, self._config())
        self.assertIn("Docker engine", str(ctx.exception))

    def test_stage_missing_src_is_provision_error(self) -> None:
        ssh = _ok_ssh()
        with self.assertRaises(ProvisionError) as ctx:
            provision(ssh, self._config(gateway_src=Path("/nonexistent-gateway-src")))
        self.assertIn("not found", str(ctx.exception).lower())

    def test_backup_then_compose(self) -> None:
        ssh = _ok_ssh(exists=True)
        with mock.patch(
            "provisioner.provision.probe_http",
            return_value=(True, "ok"),
        ):
            result = provision(ssh, self._config())
        self.assertIsNotNone(result.backup_path)
        assert result.backup_path is not None
        self.assertTrue(result.backup_path.startswith(DEFAULT_INSTALL_ROOT + ".bak-"))
        self.assertTrue(
            any(
                c.startswith("mv ") and DEFAULT_INSTALL_ROOT + ".bak-" in c
                for c in ssh.commands
            )
        )

    def test_loki_probe_failure_auto_rollback(self) -> None:
        ssh = _ok_ssh(exists=True)
        ssh.when("curl -fsS", CommandResult(7, "", "Failed to connect"))
        with mock.patch(
            "provisioner.provision.probe_http",
            return_value=(True, "ok"),
        ):
            with self.assertRaises(ProvisionError) as ctx:
                provision(ssh, self._config())
        msg = str(ctx.exception).lower()
        self.assertIn("cannot reach monitoring loki", msg)
        self.assertIn("auto-rolled back", msg)
        self.assertTrue(any("docker compose" in c and "down" in c for c in ssh.commands))

    def test_keep_failed_skips_auto_rollback(self) -> None:
        ssh = _ok_ssh(exists=True)
        ssh.when("curl -fsS", CommandResult(7, "", "Failed to connect"))
        with mock.patch(
            "provisioner.provision.probe_http",
            return_value=(True, "ok"),
        ):
            with self.assertRaises(ProvisionError) as ctx:
                provision(ssh, self._config(keep_failed=True))
        self.assertIn("keep-failed", str(ctx.exception).lower())
        self.assertFalse(any(" down" in c for c in ssh.commands))

    def test_upload_failure_restores_backup(self) -> None:
        ssh = _ok_ssh(exists=True)
        ssh.upload_tree_error = RuntimeError("sftp boom")
        with self.assertRaises(ProvisionError) as ctx:
            provision(ssh, self._config())
        self.assertIn("sftp boom", str(ctx.exception))
        self.assertTrue(any("docker compose" in c and "down" in c for c in ssh.commands))
        self.assertTrue(any(c.startswith("mv ") and ".bak-" in c for c in ssh.commands))

    def test_with_images_uploads_file_not_bytes(self) -> None:
        ssh = _ok_ssh()
        with tempfile.NamedTemporaryFile(suffix=".tar") as tf:
            tf.write(b"fake-tar")
            tf.flush()
            with mock.patch(
                "provisioner.provision.probe_http",
                return_value=(True, "ok"),
            ):
                ssh.when("docker load", CommandResult(0, "Loaded image\n", ""))
                result = provision(
                    ssh, self._config(images_tar=Path(tf.name), agent_mode="skip")
                )
        self.assertTrue(any("docker load" in c for c in ssh.commands))
        self.assertTrue(any(u[0].startswith("/tmp/iotgw-images-") for u in ssh.uploads))
        self.assertTrue(any("loaded images" in n for n in result.notes))

    def test_agent_compose_last(self) -> None:
        ssh = _ok_ssh()
        ssh.when("test -f", CommandResult(0, "OK\n", ""))
        with mock.patch(
            "provisioner.provision.probe_http",
            return_value=(True, "ok"),
        ):
            result = provision(ssh, self._config(agent_mode="compose"))
        self.assertTrue(result.agent_installed)
        self.assertEqual(result.agent_mode, "compose")
        agent_cmds = [
            c
            for c in ssh.commands
            if "docker-compose.agent.yaml" in c and "up -d agent" in c
        ]
        self.assertEqual(len(agent_cmds), 1)
        main_idx = next(
            i
            for i, c in enumerate(ssh.commands)
            if "docker compose" in c and "up -d --remove-orphans" in c
        )
        agent_idx = ssh.commands.index(agent_cmds[0])
        self.assertGreater(agent_idx, main_idx)

    def test_agent_failure_is_soft(self) -> None:
        ssh = _ok_ssh()
        ssh.when(
            "up -d agent",
            CommandResult(1, "", "compose agent failed"),
        )
        with mock.patch(
            "provisioner.provision.probe_http",
            return_value=(True, "ok"),
        ):
            result = provision(ssh, self._config(agent_mode="compose"))
        self.assertFalse(result.agent_installed)
        self.assertTrue(any("agent install failed" in n for n in result.notes))

    def test_agent_missing_is_ok(self) -> None:
        ssh = _ok_ssh()
        with tempfile.TemporaryDirectory() as tmp:
            gw = Path(tmp) / "gateway"
            (gw / "promtail" / "config").mkdir(parents=True)
            (gw / "docker-compose.yaml").write_text("services: {}\n", encoding="utf-8")
            (gw / "promtail" / "config" / "promtail-config.yaml").write_text(
                "x: 1\n", encoding="utf-8"
            )
            with mock.patch(
                "provisioner.provision.probe_http",
                return_value=(True, "ok"),
            ):
                result = provision(
                    ssh,
                    self._config(gateway_src=gw, agent_mode="auto"),
                )
        self.assertFalse(result.agent_installed)
        self.assertTrue(any("not present" in n for n in result.notes))

    def test_systemd_mode_rejected(self) -> None:
        ssh = _ok_ssh()
        with mock.patch(
            "provisioner.provision.probe_http",
            return_value=(True, "ok"),
        ):
            result = provision(ssh, self._config(agent_mode="systemd"))
        # Soft-fail path: unsupported mode becomes agent note via ProvisionError catch
        self.assertFalse(result.agent_installed)
        self.assertTrue(any("systemd" in n.lower() or "unsupported" in n.lower() for n in result.notes))

    def test_rollback_install_compose_down(self) -> None:
        ssh = FakeSSH()
        ssh.when("docker compose", CommandResult(0, "", ""))
        ssh.when("rm -rf", CommandResult(0, "", ""))
        ssh.when("mv ", CommandResult(0, "", ""))
        rollback_install(ssh, DEFAULT_INSTALL_ROOT, "/opt/iot-gateway.bak-1")
        self.assertTrue(any("down" in c for c in ssh.commands))
        self.assertTrue(any("rm -rf" in c for c in ssh.commands))
        self.assertTrue(
            any(
                c.startswith("mv ")
                and "/opt/iot-gateway.bak-1" in c
                and DEFAULT_INSTALL_ROOT in c
                for c in ssh.commands
            )
        )


if __name__ == "__main__":
    unittest.main()
