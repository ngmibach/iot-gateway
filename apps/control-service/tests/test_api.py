"""FastAPI device routes — TestClient with mocked actions/registry SSH."""

from __future__ import annotations

import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator
from unittest.mock import patch

from fastapi.testclient import TestClient

from actions.playbooks import PlaybookResult, RegisterResult
from api.app import create_app
from api.cert_cache import CertBundleCache
from api.settings import Settings
from registry.registry import Registry


class _FakeSSH:
    """Minimal stand-in; playbooks are mocked so methods are unused."""

    pass


def _register_ok(_ssh: Any = None, **kwargs: Any) -> RegisterResult:
    return RegisterResult(
        ok=True,
        status="ok",
        message="device registered",
        details={"user_id": kwargs.get("user_id"), "ip": kwargs.get("ip")},
        cert_bundle=b"PK\x03\x04fake-zip",
        cert_fingerprint="ab" * 32,
        cert_expires_at="2030-01-01T00:00:00+00:00",
    )


def _unregister_ok(_ssh: Any = None, **kwargs: Any) -> PlaybookResult:
    return PlaybookResult(ok=True, status="ok", message="unregistered")


class ApiDeviceTests(unittest.TestCase):
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
        )
        self.settings = Settings(
            host="127.0.0.1",
            port=9137,
            data_dir=Path(self._tmp.name),
            registry_path=db,
            ca_passphrase="test-ca-secret",
            api_token=None,
        )
        self.cache = CertBundleCache(ttl_s=60)

        @contextmanager
        def open_ssh(_gw: dict[str, Any]) -> Iterator[_FakeSSH]:
            yield _FakeSSH()

        self.app = create_app(
            settings=self.settings,
            registry=self.registry,
            open_ssh=open_ssh,
            cert_cache=self.cache,
        )
        self.client = TestClient(self.app)

    def test_health(self) -> None:
        r = self.client.get("/health")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["status"], "ok")
        r2 = self.client.get("/api/v1/health")
        self.assertEqual(r2.status_code, 200)

    def test_list_gateways_node_instance(self) -> None:
        r = self.client.get("/api/v1/gateways")
        self.assertEqual(r.status_code, 200)
        rows = r.json()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["id"], "gw1")
        self.assertEqual(rows[0]["node_instance"], "gateway")

    def test_register_device_upserts_registry_and_token(self) -> None:
        with patch("api.devices.register_device", side_effect=_register_ok) as mocked:
            r = self.client.post(
                "/api/v1/gateways/gw1/devices",
                json={
                    "user_id": "sensor5",
                    "password": "password123",
                    "ip": "192.168.1.60",
                    "topic_readwrite": "sensors/sensor5/#",
                    "topic_read": ["alerts/+"],
                },
            )
        self.assertEqual(r.status_code, 200, r.text)
        body = r.json()
        self.assertEqual(body["device"]["id"], "sensor5")
        self.assertEqual(body["device"]["ip"], "192.168.1.60")
        self.assertFalse(body["idempotent"])
        self.assertIsNotNone(body["cert_bundle_token"])
        mocked.assert_called_once()
        kwargs = mocked.call_args.kwargs
        self.assertEqual(kwargs["user_id"], "sensor5")
        self.assertEqual(kwargs["ip"], "192.168.1.60")
        self.assertEqual(kwargs["topic_rw"], "sensors/sensor5/#")
        self.assertEqual(kwargs["topic_r"], "alerts/+")
        self.assertEqual(kwargs["ca_passphrase"], "test-ca-secret")

        listed = self.client.get("/api/v1/gateways/gw1/devices")
        self.assertEqual(listed.status_code, 200)
        self.assertEqual(len(listed.json()), 1)

        token = body["cert_bundle_token"]
        dl = self.client.get(
            f"/api/v1/gateways/gw1/devices/sensor5/cert-bundle",
            params={"token": token},
        )
        self.assertEqual(dl.status_code, 200)
        self.assertEqual(dl.content, b"PK\x03\x04fake-zip")
        self.assertIn("application/zip", dl.headers.get("content-type", ""))

        # One-time: second download fails
        dl2 = self.client.get(
            f"/api/v1/gateways/gw1/devices/sensor5/cert-bundle",
            params={"token": token},
        )
        self.assertEqual(dl2.status_code, 404)

    def test_register_unknown_gateway_404(self) -> None:
        with patch("api.devices.register_device", side_effect=_register_ok):
            r = self.client.post(
                "/api/v1/gateways/missing/devices",
                json={
                    "user_id": "sensor5",
                    "password": "password123",
                    "ip": "10.0.0.1",
                },
            )
        self.assertEqual(r.status_code, 404)

    def test_register_playbook_failure_502(self) -> None:
        def _fail(_ssh: Any = None, **kwargs: Any) -> RegisterResult:
            return RegisterResult(ok=False, status="failed", message="boom")

        with patch("api.devices.register_device", side_effect=_fail):
            r = self.client.post(
                "/api/v1/gateways/gw1/devices",
                json={
                    "user_id": "sensor5",
                    "password": "password123",
                    "ip": "10.0.0.1",
                },
            )
        self.assertEqual(r.status_code, 502)
        self.assertIn("boom", r.json()["detail"])

    def test_delete_device(self) -> None:
        self.registry.upsert_device("gw1", "sensor1", ip="10.0.0.2")
        with patch("api.devices.unregister_device", side_effect=_unregister_ok) as mocked:
            r = self.client.delete("/api/v1/gateways/gw1/devices/sensor1")
        self.assertEqual(r.status_code, 200, r.text)
        self.assertTrue(r.json()["ok"])
        mocked.assert_called_once()
        self.assertIsNone(self.registry.get_device("gw1", "sensor1"))

    def test_api_token_required_when_configured(self) -> None:
        self.settings = Settings(
            host="127.0.0.1",
            port=9137,
            data_dir=Path(self._tmp.name),
            registry_path=Path(self._tmp.name) / "registry.sqlite",
            api_token="secret-token",
            ca_passphrase="x",
        )

        @contextmanager
        def open_ssh(_gw: dict[str, Any]) -> Iterator[_FakeSSH]:
            yield _FakeSSH()

        app = create_app(
            settings=self.settings,
            registry=self.registry,
            open_ssh=open_ssh,
            cert_cache=self.cache,
        )
        client = TestClient(app)
        denied = client.get("/api/v1/gateways")
        self.assertEqual(denied.status_code, 401)
        ok = client.get(
            "/api/v1/gateways",
            headers={"X-API-Token": "secret-token"},
        )
        self.assertEqual(ok.status_code, 200)
        # /health stays open
        self.assertEqual(client.get("/health").status_code, 200)


if __name__ == "__main__":
    unittest.main()
