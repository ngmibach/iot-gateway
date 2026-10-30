"""FakeSSH unit tests for fake sensor runtime playbooks."""

from __future__ import annotations

import json
import unittest

from actions.fake_sensors import (
    FAKE_BRIDGE,
    FAKE_GATEWAY_IP,
    FAKE_UNIT_TEMPLATE,
    allocate_fake_ip,
    create_netns,
    enable_and_start_unit,
    ensure_fake_bridge,
    ensure_fake_runtime,
    ensure_fake_unit_installed,
    feed_fake_certs,
    install_fake_files,
    netns_name,
    read_fake_allocation,
    teardown_all_fakes,
    teardown_fake,
    unit_instance,
    update_fake_config,
)
from actions.ssh import CommandResult
from tests.fake_ssh import FakeSSH

DATA = "/var/lib/iot-gateway-agent"
FAKE_DIR = f"{DATA}/fake"
IP_MAP = f"{FAKE_DIR}/ip-map.json"


class TestFakeSensorsPlaybooks(unittest.TestCase):
    def test_ensure_fake_bridge_issues_sudo_and_seeds_ip_map(self) -> None:
        ssh = FakeSSH()
        result = ensure_fake_bridge(ssh, sudo_password="s3cret")  # type: ignore[arg-type]
        self.assertTrue(result.ok)
        self.assertTrue(any("sudo -S" in c for c in ssh.commands))
        self.assertTrue(any(FAKE_BRIDGE in c for c in ssh.commands))
        self.assertTrue(any("s3cret" in s for s in ssh.stdins if s))
        self.assertFalse(any("s3cret" in c for c in ssh.commands))
        # Root-owned data dir: mkdir + chown fake/ so SFTP can write ip-map.json.
        self.assertTrue(
            any(
                "mkdir -p" in c and FAKE_DIR in c and "chown" in c
                for c in ssh.commands
            )
        )
        self.assertIn(IP_MAP, ssh.files)
        body = json.loads(ssh.read_text(IP_MAP))
        self.assertEqual(body["bridge"], FAKE_BRIDGE)
        self.assertEqual(body["gateway_ip"], FAKE_GATEWAY_IP)
        self.assertEqual(body["devices"], {})

    def test_ensure_fake_bridge_uses_sudo_n_without_password(self) -> None:
        ssh = FakeSSH()
        result = ensure_fake_bridge(ssh)  # type: ignore[arg-type]
        self.assertTrue(result.ok)
        self.assertTrue(any("sudo -n" in c for c in ssh.commands))
        self.assertFalse(any("sudo -S" in c for c in ssh.commands))

    def test_allocate_fake_ip_sequential_and_idempotent(self) -> None:
        ssh = FakeSSH()
        a1 = allocate_fake_ip(ssh, "fake1")  # type: ignore[arg-type]
        a2 = allocate_fake_ip(ssh, "fake2")  # type: ignore[arg-type]
        a1b = allocate_fake_ip(ssh, "fake1")  # type: ignore[arg-type]
        self.assertEqual(a1.ip, "10.255.0.2")
        self.assertEqual(a2.ip, "10.255.0.3")
        self.assertEqual(a1b.ip, a1.ip)
        self.assertEqual(a1.host_if, "vf2")
        self.assertEqual(a1.ns_if, "vn2")
        self.assertEqual(a1.netns, "iotgw-fake-fake1")
        self.assertEqual(a1.unit, "iotgw-fake@fake1")
        body = json.loads(ssh.read_text(IP_MAP))
        self.assertIn("fake1", body["devices"])
        self.assertIn("fake2", body["devices"])

    def test_allocate_rejects_invalid_user_id(self) -> None:
        ssh = FakeSSH()
        with self.assertRaises(ValueError):
            allocate_fake_ip(ssh, "../evil")  # type: ignore[arg-type]

    def test_create_netns_builds_veth_and_routes(self) -> None:
        ssh = FakeSSH()
        result = create_netns(ssh, "fake1", sudo_password="pw")  # type: ignore[arg-type]
        self.assertTrue(result.ok)
        joined = "\n".join(ssh.commands)
        self.assertIn("ip netns add", joined)
        self.assertIn("type veth", joined)
        self.assertIn("master", joined)
        self.assertIn(FAKE_BRIDGE, joined)
        self.assertIn("10.255.0.2/24", joined)
        self.assertIn(FAKE_GATEWAY_IP, joined)
        self.assertEqual(result.details["allocation"]["ip"], "10.255.0.2")

    def test_ensure_fake_unit_installed_copies_template(self) -> None:
        ssh = FakeSSH()
        result = ensure_fake_unit_installed(ssh, sudo_password="pw")  # type: ignore[arg-type]
        self.assertTrue(result.ok)
        joined = "\n".join(ssh.commands)
        self.assertIn(FAKE_UNIT_TEMPLATE, joined)
        self.assertIn("systemctl daemon-reload", joined)
        self.assertTrue(
            any("/tmp/iotgw-fake@.service" in c and "cp " in c for c in ssh.commands)
        )

    def test_ensure_fake_runtime_combines_bridge_and_unit(self) -> None:
        ssh = FakeSSH()
        result = ensure_fake_runtime(ssh, sudo_password="pw")  # type: ignore[arg-type]
        self.assertTrue(result.ok)
        self.assertEqual(result.details.get("bridge"), FAKE_BRIDGE)
        self.assertEqual(result.details.get("unit_template"), FAKE_UNIT_TEMPLATE)

    def test_install_fake_files_and_feed_certs(self) -> None:
        ssh = FakeSSH()
        installed = install_fake_files(
            ssh,  # type: ignore[arg-type]
            "fake1",
            config={
                "mqtt_password": "hunter2",
                "send_interval_ms": 500,
                "topic": "sensors/fake1/#",
            },
            payload={"temp": 21},
        )
        self.assertTrue(installed.ok)
        cfg = json.loads(ssh.read_text(f"{FAKE_DIR}/fake1/config.json"))
        self.assertEqual(cfg["mqtt_password"], "hunter2")
        self.assertEqual(cfg["broker_host"], FAKE_GATEWAY_IP)
        self.assertEqual(cfg["broker_port"], 8883)
        self.assertFalse(cfg["behaviors"]["omit_client_cert"])
        payload = json.loads(ssh.read_text(f"{FAKE_DIR}/fake1/payload.json"))
        self.assertEqual(payload["temp"], 21)

        fed = feed_fake_certs(
            ssh,  # type: ignore[arg-type]
            "fake1",
            ca_pem="-----BEGIN CERTIFICATE-----\nCA\n-----END CERTIFICATE-----\n",
            client_crt_pem="-----BEGIN CERTIFICATE-----\nCRT\n-----END CERTIFICATE-----\n",
            client_key_pem="-----BEGIN PRIVATE KEY-----\nKEY\n-----END PRIVATE KEY-----\n",
            restart=True,
            sudo_password="pw",
        )
        self.assertTrue(fed.ok)
        self.assertIn(f"{FAKE_DIR}/fake1/certs/ca.crt", ssh.files)
        self.assertIn(f"{FAKE_DIR}/fake1/certs/client.crt", ssh.files)
        self.assertIn(f"{FAKE_DIR}/fake1/certs/client.key", ssh.files)
        self.assertTrue(
            any("systemctl restart" in c and "iotgw-fake@fake1" in c for c in ssh.commands)
        )

    def test_feed_fake_certs_restart_false_skips_systemctl(self) -> None:
        ssh = FakeSSH()
        ssh.run(f"mkdir -p {FAKE_DIR}/fake1/certs")
        before = list(ssh.commands)
        fed = feed_fake_certs(
            ssh,  # type: ignore[arg-type]
            "fake1",
            ca_pem="CA",
            client_crt_pem="CRT",
            client_key_pem="KEY",
            restart=False,
        )
        self.assertTrue(fed.ok)
        new_cmds = ssh.commands[len(before) :]
        self.assertFalse(any("systemctl restart" in c for c in new_cmds))

    def test_update_fake_config_merges_behaviors(self) -> None:
        ssh = FakeSSH()
        install_fake_files(
            ssh,  # type: ignore[arg-type]
            "fake1",
            config={"mqtt_password": "x"},
        )
        updated = update_fake_config(
            ssh,  # type: ignore[arg-type]
            "fake1",
            updates={
                "send_interval_ms": 2000,
                "behaviors": {"omit_client_cert": True},
            },
            restart=False,
        )
        self.assertTrue(updated.ok)
        cfg = json.loads(ssh.read_text(f"{FAKE_DIR}/fake1/config.json"))
        self.assertEqual(cfg["send_interval_ms"], 2000)
        self.assertTrue(cfg["behaviors"]["omit_client_cert"])
        self.assertFalse(cfg["behaviors"]["wrong_password"])

    def test_enable_and_start_unit(self) -> None:
        def handler(command: str) -> CommandResult:
            if "systemctl is-active" in command:
                return CommandResult(
                    argv=command, exit_code=0, stdout="active\n", stderr=""
                )
            return CommandResult(argv=command, exit_code=0, stdout="", stderr="")

        ssh = FakeSSH(run_handler=handler)
        result = enable_and_start_unit(ssh, "fake1", sudo_password="pw")  # type: ignore[arg-type]
        self.assertTrue(result.ok, result.message)
        joined = "\n".join(ssh.commands)
        # Reboot drops /run/netns — start must recreate it and refresh the unit.
        self.assertIn("ip netns add", joined)
        self.assertIn("fake_netns.py", joined)
        self.assertIn(FAKE_UNIT_TEMPLATE, joined)
        self.assertTrue(
            any(
                "systemctl enable" in c and "iotgw-fake@fake1" in c for c in ssh.commands
            )
        )
        self.assertTrue(
            any(
                "systemctl restart" in c and "iotgw-fake@fake1" in c for c in ssh.commands
            )
        )

    def test_teardown_removes_netns_files_and_frees_ip(self) -> None:
        ssh = FakeSSH()
        create_netns(ssh, "fake1", sudo_password="pw")  # type: ignore[arg-type]
        install_fake_files(ssh, "fake1", config={"mqtt_password": "x"})  # type: ignore[arg-type]
        self.assertIsNotNone(read_fake_allocation(ssh, "fake1"))  # type: ignore[arg-type]
        torn = teardown_fake(ssh, "fake1", sudo_password="pw")  # type: ignore[arg-type]
        self.assertTrue(torn.ok)
        joined = "\n".join(ssh.commands)
        self.assertIn("systemctl stop", joined)
        self.assertIn("ip netns del", joined)
        self.assertIn("ip link del", joined)
        self.assertNotIn(f"{FAKE_DIR}/fake1/config.json", ssh.files)
        body = json.loads(ssh.read_text(IP_MAP))
        self.assertNotIn("fake1", body["devices"])
        # IP reusable after teardown.
        again = allocate_fake_ip(ssh, "fake1")  # type: ignore[arg-type]
        self.assertEqual(again.ip, "10.255.0.2")

    def test_teardown_all_fakes_clears_bridge_netns_and_dir(self) -> None:
        ssh = FakeSSH()
        create_netns(ssh, "fake1", sudo_password="pw")  # type: ignore[arg-type]
        create_netns(ssh, "fake2", sudo_password="pw")  # type: ignore[arg-type]
        install_fake_files(ssh, "fake1", config={"mqtt_password": "x"})  # type: ignore[arg-type]
        install_fake_files(ssh, "fake2", config={"mqtt_password": "y"})  # type: ignore[arg-type]
        torn = teardown_all_fakes(ssh, sudo_password="pw")  # type: ignore[arg-type]
        self.assertTrue(torn.ok, torn.message)
        joined = "\n".join(ssh.commands)
        self.assertIn("iotgw-fake@*", joined)
        self.assertIn("ip netns list", joined)
        self.assertIn("ip link del", joined)
        self.assertIn(FAKE_BRIDGE, joined)
        self.assertIn(FAKE_UNIT_TEMPLATE, joined)
        self.assertTrue(
            not any(p == FAKE_DIR or p.startswith(FAKE_DIR + "/") for p in ssh.files),
            ssh.files.keys(),
        )
        self.assertEqual(torn.details.get("device_count"), 2)

    def test_bridge_failure_surfaces_message(self) -> None:
        def handler(cmd: str) -> CommandResult:
            if "iotgw-fake" in cmd and "sudo" in cmd:
                return CommandResult(argv=cmd, exit_code=1, stdout="", stderr="no bridge")
            return CommandResult(argv=cmd, exit_code=0, stdout="", stderr="")

        ssh = FakeSSH(run_handler=handler)
        result = ensure_fake_bridge(ssh, sudo_password="pw")  # type: ignore[arg-type]
        self.assertFalse(result.ok)
        self.assertEqual(result.status, "failed")
        self.assertIn("bridge", result.message.lower())

    def test_helpers_validate_names(self) -> None:
        self.assertEqual(netns_name("sensor_1"), "iotgw-fake-sensor_1")
        self.assertEqual(unit_instance("sensor_1"), "iotgw-fake@sensor_1")
        with self.assertRaises(ValueError):
            netns_name("bad id")


if __name__ == "__main__":
    unittest.main()
