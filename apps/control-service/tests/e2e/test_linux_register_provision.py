"""CI-friendly E2E: mocked Linux provision + real register playbook + API."""

from __future__ import annotations

import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator
from unittest.mock import patch

from fastapi.testclient import TestClient

from actions.playbooks import RegisterResult
from api.app import create_app
from api.cert_cache import CertBundleCache
from api.settings import Settings
from registry.registry import Registry
from tests.e2e.linux_happy_path import (
    PROVISION_STEPS,
    mock_provision,
    run_linux_happy_path_mocked,
    run_live_checklist,
)
from tests.fake_ssh import FakeSSH


class LinuxHappyPathMockedTests(unittest.TestCase):
    def test_provision_then_register_happy_path(self) -> None:
        result = run_linux_happy_path_mocked()
        self.assertTrue(result["ok"], msg=result)
        self.assertEqual(result["phase"], "done")
        self.assertEqual(
            result["provision"].steps_completed, list(PROVISION_STEPS)
        )
        self.assertTrue(result["acl_has_user"])
        self.assertTrue(result["allowlist_has_ip"])
        self.assertTrue(result["password_not_plaintext"])
        self.assertTrue(result["nodered_in_compose"])  # K17
        self.assertIn("node_exporter", result["provision"].probes)
        self.assertIn("loki", result["provision"].probes)

    def test_provision_failure_stops_before_register(self) -> None:
        ssh = FakeSSH()
        prov = mock_provision(
            ssh,
            gateway_ip="192.168.1.50",
            monitoring_ip="192.168.1.20",
            fail_at="compose_up",
        )
        self.assertFalse(prov.ok)
        self.assertIn("compose_up", prov.message)
        self.assertNotIn("compose_up", prov.steps_completed)
        self.assertIn("stage_upload_bundle", prov.steps_completed)

    def test_live_checklist_documents_flow(self) -> None:
        text = run_live_checklist()
        self.assertIn("provisioner", text)
        self.assertIn("nodered", text.lower())
        self.assertIn("GATEWAY_IP", text)


class LinuxRegisterApiIntegrationTests(unittest.TestCase):
    """Register via FastAPI after a mocked provision (still no live SSH)."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        db = Path(self._tmp.name) / "registry.sqlite"
        self.registry = Registry(str(db))
        self.registry.upsert_gateway(
            id="gw1",
            host="192.168.1.50",
            ssh_user="pi",
            install_root="/opt/iot-gateway",
            fingerprint="fp-test",
            monitoring_ip="192.168.1.20",
        )
        self.settings = Settings(
            host="127.0.0.1",
            port=9137,
            data_dir=Path(self._tmp.name),
            registry_path=db,
            ca_passphrase="test-ca-secret",
        )

        @contextmanager
        def open_ssh(_gw: dict[str, Any]) -> Iterator[FakeSSH]:
            yield FakeSSH()

        self.app = create_app(
            settings=self.settings,
            registry=self.registry,
            open_ssh=open_ssh,
            cert_cache=CertBundleCache(ttl_s=60),
        )
        self.client = TestClient(self.app)

    def test_api_register_after_mock_provision(self) -> None:
        # Provision is a separate SSH concern; API path registers into registry.
        prov = mock_provision(
            FakeSSH(),
            gateway_ip="192.168.1.50",
            monitoring_ip="192.168.1.20",
        )
        self.assertTrue(prov.ok)

        fake = RegisterResult(
            ok=True,
            status="ok",
            message="device registered",
            details={"user_id": "sensor9", "ip": "10.0.0.9"},
            cert_bundle=b"PK\x03\x04fake-zip",
            cert_fingerprint="cd" * 32,
            cert_expires_at="2030-01-01T00:00:00+00:00",
        )
        with patch("api.devices.register_device", return_value=fake):
            resp = self.client.post(
                "/api/v1/gateways/gw1/devices",
                json={
                    "user_id": "sensor9",
                    "password": "hunter2-ok",
                    "ip": "10.0.0.9",
                    "topic_readwrite": ["sensors/sensor9/#"],
                    "topic_read": ["alerts/+"],
                },
            )
        self.assertEqual(resp.status_code, 200, resp.text)
        body = resp.json()
        self.assertEqual(body["device"]["id"], "sensor9")
        self.assertIn("cert_bundle_token", body)
        devices = self.client.get("/api/v1/gateways/gw1/devices")
        self.assertEqual(devices.status_code, 200)
        ids = {d["id"] for d in devices.json()}
        self.assertIn("sensor9", ids)


if __name__ == "__main__":
    unittest.main()
