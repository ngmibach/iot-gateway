from __future__ import annotations

import json
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator
from unittest.mock import patch

from fastapi.testclient import TestClient

from api.app import create_app
from api.settings import Settings
from provisioner.ssh import CommandResult
from registry.registry import Registry


class _FakeIDSSSH:
    def __init__(self) -> None:
        self.enabled = False
        self.commands: list[str] = []
        self.stdins: list[str | None] = []
        self.uploaded: dict[str, bytes] = {}
        self.pending_config: dict[str, Any] | None = None
        self.config: dict[str, Any] = {
            "gateway": {
                "enabled": False,
                "ml_enabled": True,
                "suspicious_threshold": None,
                "behavioral_rules": {
                    "enabled": True,
                    "max_message_rate_per_sec": 1.5,
                },
            },
            "model": {"path": "models/ids_model.joblib"},
        }

    def run(
        self,
        command: str,
        *,
        timeout: float = 30.0,
        stdin: str | None = None,
    ) -> CommandResult:
        self.commands.append(command)
        self.stdins.append(stdin)
        if "systemctl show" in command:
            active = "active" if self.enabled else "inactive"
            sub = "running" if self.enabled else "dead"
            return CommandResult(
                0,
                f"LoadState=loaded\nActiveState={active}\n"
                f"SubState={sub}\nResult=success\n",
                "",
            )
        if "printf 'config=%s" in command:
            return CommandResult(0, "config=1\nmodel=1\nruntime=1\n", "")
        if "yaml.safe_load(p)" in command:
            return CommandResult(0, json.dumps(self.config), "")
        if "yaml.safe_dump" in command:
            self.pending_config = json.loads(stdin or "{}")
            return CommandResult(0, "gateway:\n  enabled: true\n", "")
        if "install -o root" in command:
            assert self.pending_config is not None
            self.config = self.pending_config
        if "systemctl enable --now" in command:
            self.enabled = True
        elif "systemctl disable --now" in command:
            self.enabled = False
        return CommandResult(0, "", "")

    def upload_file(self, local_path: Path, remote_path: str, *, mode: int = 0o644) -> None:
        self.uploaded[remote_path] = Path(local_path).read_bytes()

    def close(self) -> None:
        pass


class IDSApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.registry = Registry(str(root / "registry.sqlite"))
        self.addCleanup(self.registry.close)
        self.registry.upsert_gateway(
            id="gw1",
            host="192.168.1.50",
            ssh_user="pi",
            install_root="/opt/iot-gateway-agent",
            fingerprint="fp-test",
        )
        self.ssh = _FakeIDSSSH()

        @contextmanager
        def open_ssh(_gateway: dict[str, Any]) -> Iterator[_FakeIDSSSH]:
            yield self.ssh

        self.settings = Settings(
            host="127.0.0.1",
            port=9137,
            data_dir=root,
            registry_path=root / "registry.sqlite",
            loki_url="http://loki.test:3100",
            prometheus_url="http://prom.test:9090",
        )
        app = create_app(
            settings=self.settings,
            registry=self.registry,
            open_ssh=open_ssh,
        )
        self.client = TestClient(app)

    def test_status_reports_install_model_and_service_state(self) -> None:
        response = self.client.get("/api/v1/gateways/gw1/ids/status")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            {
                "gateway_id": "gw1",
                "installed": True,
                "configured_enabled": False,
                "service_state": "stopped",
                "active_state": "inactive",
                "sub_state": "dead",
                "result": "success",
                "model_ready": True,
                "runtime_ready": True,
                "config": self.ssh.config["gateway"],
            },
        )

    def test_config_update_atomically_applies_settings_and_service_state(self) -> None:
        response = self.client.post(
            "/api/v1/gateways/gw1/ids/config",
            json={
                "enabled": True,
                "threshold": 0.7,
                "max_message_rate_per_sec": 8.0,
                "sudo_password": "secret-password",
            },
        )

        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["service_state"], "running")
        self.assertTrue(response.json()["configured_enabled"])
        self.assertEqual(self.ssh.config["gateway"]["suspicious_threshold"], 0.7)
        self.assertEqual(
            self.ssh.config["gateway"]["behavioral_rules"][
                "max_message_rate_per_sec"
            ],
            8.0,
        )
        self.assertEqual(len(self.ssh.uploaded), 1)
        self.assertNotIn(
            "secret-password", "\n".join(self.ssh.commands)
        )
        self.assertNotIn("sudo_password", json.dumps(self.ssh.config))
        self.assertIn("secret-password", self.ssh.stdins)

    def test_config_update_rejects_out_of_range_threshold(self) -> None:
        response = self.client.post(
            "/api/v1/gateways/gw1/ids/config",
            json={"threshold": 1.01, "sudo_password": "secret-password"},
        )

        self.assertEqual(response.status_code, 422)

    def test_alert_query_is_scoped_to_gateway_host(self) -> None:
        class FakeResponse:
            status_code = 200
            text = ""

            @staticmethod
            def json() -> dict[str, Any]:
                return {
                    "data": {
                        "result": [
                            {
                                "values": [
                                    [
                                        "1700000000000000000",
                                        json.dumps(
                                            {
                                                "event_type": "ids_alert",
                                                "severity": "high",
                                                "device_id": "sensor-a",
                                            }
                                        ),
                                    ]
                                ]
                            }
                        ]
                    }
                }

        class FakeHTTP:
            params: dict[str, Any] = {}

            def get(self, _url: str, *, params: dict[str, Any]) -> FakeResponse:
                self.params = params
                return FakeResponse()

        fake_http = FakeHTTP()
        with patch("api.ids._http_client", return_value=fake_http):
            response = self.client.get(
                "/api/v1/ids/alerts?range=1h&gateway_id=gw1&severity=high"
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["count"], 1)
        self.assertEqual(response.json()["alerts"][0]["device_id"], "sensor-a")
        self.assertIn('gateway="192.168.1.50"', fake_http.params["query"])
        self.assertIn('severity="high"', fake_http.params["query"])


if __name__ == "__main__":
    unittest.main()
