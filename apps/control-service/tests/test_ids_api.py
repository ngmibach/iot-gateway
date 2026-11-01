"""IDS routes use authenticated SSH control and Loki alert queries."""

from __future__ import annotations

import json
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator
from unittest.mock import patch

import yaml
from fastapi.testclient import TestClient

from api.app import create_app
from api.settings import Settings
from provisioner.ssh import CommandResult
from registry.registry import Registry


_INITIAL_CONFIG = {
    "enabled": True,
    "gateway": {
        "suspicious_threshold": 0.05,
        "ip_avg_score_threshold": 0.68,
        "ml_enabled": True,
        "behavioral_rules": {
            "enabled": True,
            "max_message_rate_per_sec": 1.5,
            "max_clock_skew_seconds": 2.5,
            "max_connect_publish_ratio": 1.15,
            "alert_cooldown_seconds": 60,
        },
    },
}


class _FakeSSH:
    def __init__(self) -> None:
        self.config = yaml.safe_dump(_INITIAL_CONFIG)
        self.uploaded: bytes | None = None
        self.commands: list[str] = []
        self.service_active = True
        self.installed = True

    def read_text(self, path: str) -> str:
        if path != "/var/lib/iot-gateway-agent/ids_config.yaml":
            raise AssertionError(f"unexpected config path: {path}")
        return self.config

    def upload_file(self, local_path: Path, remote_path: str, *, mode: int = 0o644) -> None:
        self.uploaded = Path(local_path).read_bytes()
        self.remote_tmp = remote_path

    def run(self, command: str, *, timeout: float = 120.0, stdin: str | None = None):
        self.commands.append(command)
        output = [
            "LoadState=loaded" if self.installed else "LoadState=not-found",
            "ActiveState=active" if self.service_active else "ActiveState=inactive",
            "SubState=running" if self.service_active else "SubState=dead",
            "Result=success",
        ]
        if self.installed:
            output.extend(
                [
                    "unit_present=1",
                    "config_present=1",
                    "model_present=1",
                    "runtime_present=1",
                ]
            )
        return CommandResult(0, "\n".join(output), "")


class IDSApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        root = Path(self.temp_dir.name)
        self.registry = Registry(str(root / "registry.sqlite"))
        self.addCleanup(self.registry.close)
        self.registry.upsert_gateway(
            id="gw1",
            host="192.0.2.8",
            ssh_user="iot",
            install_root="/opt/iot-gateway-agent",
            fingerprint="pinned",
        )
        self.ssh = _FakeSSH()

        @contextmanager
        def open_ssh(_gateway: dict[str, Any]) -> Iterator[_FakeSSH]:
            yield self.ssh

        self.open_ssh = open_ssh
        settings = Settings(
            data_dir=root,
            registry_path=root / "registry.sqlite",
            loki_url="http://127.0.0.1:3100",
            fake_cert_renewer_enabled=False,
            api_token="ids-api-test-token",
        )
        self.app = create_app(
            settings=settings,
            registry=self.registry,
            open_ssh=open_ssh,
            start_fake_cert_renewer=False,
        )
        self.client = TestClient(
            self.app, headers={"X-API-Token": "ids-api-test-token"}
        )

    def test_reads_config_and_actual_runtime_status(self) -> None:
        config = self.client.get("/api/v1/gateways/gw1/ids/config")
        self.assertEqual(config.status_code, 200, config.text)
        self.assertEqual(config.json()["threshold"], 0.05)

        status = self.client.get("/api/v1/gateways/gw1/ids/status")
        self.assertEqual(status.status_code, 200, status.text)
        self.assertTrue(status.json()["installed"])
        self.assertTrue(status.json()["configured_enabled"])
        self.assertTrue(status.json()["runtime_ready"])
        self.assertEqual(status.json()["service_state"], "running")

    def test_config_update_changes_only_ids_service_and_confirms_status(self) -> None:
        body = {
            "enabled": True,
            "rules_enabled": False,
            "ml_enabled": True,
            "threshold": 0.42,
            "max_message_rate_per_sec": 2.5,
            "max_clock_skew_seconds": 3.0,
            "max_connect_publish_ratio": 1.7,
            "alert_cooldown_seconds": 30,
            "sudo_password": "temporary-sudo-password",
        }

        def apply(ssh: _FakeSSH, command: str, *, sudo_password: str, timeout: float):
            self.assertEqual(sudo_password, "temporary-sudo-password")
            self.assertNotIn(sudo_password, command)
            self.assertNotIn("systemctl restart iot-gateway-agent", command)
            self.assertIn("systemctl restart iot-gateway-ids.service", command)
            saved = yaml.safe_load(ssh.uploaded)
            ssh.config = yaml.safe_dump(saved)
            ssh.service_active = bool(saved["enabled"])
            return CommandResult(0, "", "")

        with patch("api.ids.sudo_run", side_effect=apply):
            response = self.client.post(
                "/api/v1/gateways/gw1/ids/config",
                json=body,
            )
        self.assertEqual(response.status_code, 200, response.text)
        self.assertTrue(response.json()["ok"])
        self.assertEqual(response.json()["config"]["threshold"], 0.42)
        self.assertTrue(response.json()["status"]["runtime_ready"])
        self.assertNotIn("sudo_password", response.text)
        saved = yaml.safe_load(self.ssh.config)
        self.assertFalse(saved["gateway"]["behavioral_rules"]["enabled"])
        self.assertEqual(saved["gateway"]["ip_avg_score_threshold"], 0.68)

    def test_disable_stops_only_ids_service(self) -> None:
        body = {
            "enabled": False,
            "rules_enabled": True,
            "ml_enabled": True,
            "threshold": 0.05,
            "max_message_rate_per_sec": 1.5,
            "max_clock_skew_seconds": 2.5,
            "max_connect_publish_ratio": 1.15,
            "alert_cooldown_seconds": 60,
            "sudo_password": "secret",
        }

        def apply(ssh: _FakeSSH, command: str, **_kwargs):
            self.assertIn("systemctl disable --now iot-gateway-ids.service", command)
            self.assertNotIn("systemctl restart iot-gateway-agent", command)
            self.assertNotIn("systemctl stop iot-gateway-agent", command)
            saved = yaml.safe_load(ssh.uploaded)
            ssh.config = yaml.safe_dump(saved)
            ssh.service_active = False
            return CommandResult(0, "", "")

        with patch("api.ids.sudo_run", side_effect=apply):
            response = self.client.post("/api/v1/gateways/gw1/ids/config", json=body)
        self.assertEqual(response.status_code, 200, response.text)
        self.assertFalse(response.json()["status"]["runtime_ready"])
        self.assertEqual(response.json()["status"]["service_state"], "stopped")

    def test_invalid_bounds_and_missing_gateway(self) -> None:
        bad = {
            "enabled": True,
            "rules_enabled": True,
            "ml_enabled": True,
            "threshold": 1.5,
            "max_message_rate_per_sec": 1.5,
            "max_clock_skew_seconds": 2.5,
            "max_connect_publish_ratio": 1.15,
            "alert_cooldown_seconds": 60,
            "sudo_password": "secret",
        }
        self.assertEqual(
            self.client.post("/api/v1/gateways/gw1/ids/config", json=bad).status_code,
            422,
        )
        self.assertEqual(
            self.client.get("/api/v1/gateways/missing/ids/status").status_code,
            404,
        )

    def test_routes_require_control_api_token(self) -> None:
        unauthenticated = TestClient(self.app)
        response = unauthenticated.get("/api/v1/gateways/gw1/ids/status")
        self.assertEqual(response.status_code, 401, response.text)

    def test_uninstalled_state_is_not_reported_as_healthy(self) -> None:
        self.ssh.installed = False
        status = self.client.get("/api/v1/gateways/gw1/ids/status")
        self.assertEqual(status.status_code, 200, status.text)
        self.assertFalse(status.json()["installed"])
        self.assertEqual(status.json()["service_state"], "not_installed")
        self.assertFalse(status.json()["runtime_ready"])

    def test_alerts_are_gateway_filtered_and_structured(self) -> None:
        alert = {
            "event_type": "ids_alert",
            "severity": "critical",
            "device_id": "sensor4",
            "detection": "message_pattern_anomaly",
            "message": "suspicious activity",
            "score": 0.91,
            "@timestamp": "2026-10-21T12:30:00+00:00",
        }
        with patch(
            "api.ids._proxy_get",
            return_value={"data": {"result": [{"values": [["1", json.dumps(alert)]]}] }},
        ) as query:
            response = self.client.get("/api/v1/ids/alerts?range=1h&gateway_id=gw1")
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["count"], 1)
        self.assertEqual(response.json()["alerts"][0]["device_id"], "sensor4")
        self.assertTrue(response.json()["alerts"][0]["id"])
        self.assertIn('gateway="192.0.2.8"', query.call_args.args[1]["query"])


if __name__ == "__main__":
    unittest.main()
