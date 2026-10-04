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
        self.closed = False

    def when(self, substr: str, result: CommandResult | None = None, *, contains: bool = True):
        """Register a response when command matches substr."""
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

    def upload_bytes(self, data: bytes, remote_path: str, *, mode: int = 0o644) -> None:
        self.uploads.append((remote_path, mode))
        self.files[remote_path] = data

    def upload_tree(self, local_dir: Path, remote_dir: str) -> None:
        self.trees.append((str(local_dir), remote_dir))

    def close(self) -> None:
        self.closed = True


def _ok_ssh(*, exists: bool = False, free_k: int = 5_000_000) -> FakeSSH:
    """Fake SSH that passes docker + disk preflight."""
    ssh = FakeSSH()
    ssh.when("docker info", CommandResult(0, "OK\n", ""))
    # df -Pk line: Filesystem 1024-blocks Used Available Capacity Mounted
    df_line = f"/dev/sda1 20000000 1000000 {free_k} 5% /opt\n"
    ssh.when("df -Pk", CommandResult(0, df_line, ""))
    if exists:
        ssh.when(
            f"if [ -e '{DEFAULT_INSTALL_ROOT}' ]",
            CommandResult(0, "EXISTS\n", ""),
        )
    else:
        ssh.when(
            f"if [ -e '{DEFAULT_INSTALL_ROOT}' ]",
            CommandResult(0, "", ""),
        )
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
    def test_latest_backup(self) -> None:
        paths = [
            "/opt/iot-gateway.bak-100",
            "/opt/iot-gateway.bak-250",
            "/opt/other.bak-999",
            "/opt/iot-gateway.bak-200",
        ]
        self.assertEqual(latest_backup_path(paths), "/opt/other.bak-999")


class BundleStageTests(unittest.TestCase):
    def test_renders_promtail_monitoring_ip(self) -> None:
        repo = Path(__file__).resolve().parents[4]
        gateway = repo / "gateway"
        templates = repo / "deploy" / "templates"
        with tempfile.TemporaryDirectory() as tmp:
            staged = stage_gateway_bundle(
                gateway,
                Path(tmp) / "stage",
                values={"GATEWAY_IP": "10.0.0.5", "MONITORING_IP": "10.0.0.9"},
                template_dir=templates,
                repo_root=repo,
            )
            promtail = (
                staged / "promtail" / "config" / "promtail-config.yaml"
            ).read_text(encoding="utf-8")
            self.assertIn("http://10.0.0.9:3100/loki/api/v1/push", promtail)
            self.assertNotIn("{{MONITORING_IP}}", promtail)
            self.assertTrue((staged / "docker-compose.yaml").is_file())


class ProvisionFlowTests(unittest.TestCase):
    def setUp(self) -> None:
        self.repo = Path(__file__).resolve().parents[4]
        # Avoid multi-minute probe retries in unit tests.
        self._retry_patch = mock.patch("provisioner.provision.PROBE_RETRIES", 1)
        self._interval_patch = mock.patch("provisioner.provision.PROBE_INTERVAL_S", 0)
        self._retry_patch.start()
        self._interval_patch.start()

    def tearDown(self) -> None:
        self._retry_patch.stop()
        self._interval_patch.stop()

    def _config(self, **kwargs) -> ProvisionConfig:
        base = dict(
            gateway_ip="192.168.1.50",
            monitoring_ip="192.168.1.10",
            gateway_src=self.repo / "gateway",
            template_dir=self.repo / "deploy" / "templates",
            repo_root=self.repo,
            agent_mode="skip",
        )
        base.update(kwargs)
        return ProvisionConfig(**base)

    def test_happy_path_skips_agent(self) -> None:
        ssh = _ok_ssh()
        with mock.patch(
            "provisioner.provision._wait_http",
            return_value=(True, "ok"),
        ):
            result = provision(ssh, self._config())
        self.assertEqual(result.install_root, DEFAULT_INSTALL_ROOT)
        self.assertFalse(result.agent_installed)
        self.assertEqual(len(ssh.trees), 1)
        self.assertEqual(ssh.trees[0][1], DEFAULT_INSTALL_ROOT)
        self.assertTrue(any("docker compose" in c and "up -d" in c for c in ssh.commands))
        self.assertIn("loki_from_gateway", result.probes)
        self.assertTrue(
            any("no --with-images" in n or "cold pull" in n for n in result.notes)
        )

    def test_disk_preflight_aborts(self) -> None:
        ssh = _ok_ssh(free_k=100)  # 100 KiB free
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

    def test_backup_then_compose(self) -> None:
        ssh = _ok_ssh(exists=True)
        ssh.when("mv '/opt/iot-gateway'", CommandResult(0, "", ""))
        with mock.patch(
            "provisioner.provision._wait_http",
            return_value=(True, "ok"),
        ):
            result = provision(ssh, self._config())
        self.assertIsNotNone(result.backup_path)
        assert result.backup_path is not None
        self.assertTrue(result.backup_path.startswith(DEFAULT_INSTALL_ROOT + ".bak-"))
        self.assertTrue(any(c.startswith("mv ") for c in ssh.commands))

    def test_loki_probe_failure_message(self) -> None:
        ssh = _ok_ssh()
        ssh.when("curl -fsS", CommandResult(7, "", "Failed to connect"))
        with mock.patch(
            "provisioner.provision._wait_http",
            return_value=(True, "ok"),
        ):
            with self.assertRaises(ProvisionError) as ctx:
                provision(ssh, self._config())
        self.assertIn("cannot reach monitoring loki", str(ctx.exception).lower())

    def test_with_images_uploads_and_loads(self) -> None:
        ssh = _ok_ssh()
        with tempfile.NamedTemporaryFile(suffix=".tar") as tf:
            tf.write(b"fake-tar")
            tf.flush()
            with mock.patch(
                "provisioner.provision._wait_http",
                return_value=(True, "ok"),
            ):
                # docker load handler
                ssh.when("docker load", CommandResult(0, "Loaded image\n", ""))
                result = provision(
                    ssh, self._config(images_tar=Path(tf.name), agent_mode="skip")
                )
        self.assertTrue(any("docker load" in c for c in ssh.commands))
        self.assertTrue(any(u[0].startswith("/tmp/iotgw-images-") for u in ssh.uploads))
        self.assertTrue(any("loaded images" in n for n in result.notes))

    def test_agent_compose_last(self) -> None:
        ssh = _ok_ssh()
        # Ensure agent overlay "exists" on remote
        ssh.when("test -f", CommandResult(0, "OK\n", ""))
        with mock.patch(
            "provisioner.provision._wait_http",
            return_value=(True, "ok"),
        ):
            result = provision(ssh, self._config(agent_mode="compose"))
        self.assertTrue(result.agent_installed)
        self.assertEqual(result.agent_mode, "compose")
        agent_cmds = [c for c in ssh.commands if "docker-compose.agent.yaml" in c and "up -d agent" in c]
        self.assertEqual(len(agent_cmds), 1)
        # Agent command must come after the main compose up.
        main_idx = next(
            i
            for i, c in enumerate(ssh.commands)
            if "docker compose" in c and "up -d --remove-orphans" in c
        )
        agent_idx = ssh.commands.index(agent_cmds[0])
        self.assertGreater(agent_idx, main_idx)

    def test_agent_missing_is_ok(self) -> None:
        ssh = _ok_ssh()
        with tempfile.TemporaryDirectory() as tmp:
            gw = Path(tmp) / "gateway"
            # Minimal fake gateway without agent/
            (gw / "promtail" / "config").mkdir(parents=True)
            (gw / "docker-compose.yaml").write_text("services: {}\n", encoding="utf-8")
            (gw / "promtail" / "config" / "promtail-config.yaml").write_text(
                "x: 1\n", encoding="utf-8"
            )
            with mock.patch(
                "provisioner.provision._wait_http",
                return_value=(True, "ok"),
            ):
                result = provision(
                    ssh,
                    self._config(gateway_src=gw, agent_mode="auto"),
                )
        self.assertFalse(result.agent_installed)
        self.assertTrue(any("not present" in n for n in result.notes))

    def test_rollback_install(self) -> None:
        ssh = FakeSSH()
        ssh.when("rm -rf", CommandResult(0, "", ""))
        ssh.when("mv ", CommandResult(0, "", ""))
        rollback_install(ssh, DEFAULT_INSTALL_ROOT, "/opt/iot-gateway.bak-1")
        self.assertTrue(any("rm -rf" in c for c in ssh.commands))
        self.assertTrue(
            any(
                "mv '/opt/iot-gateway.bak-1' '/opt/iot-gateway'" in c
                for c in ssh.commands
            )
        )


if __name__ == "__main__":
    unittest.main()
