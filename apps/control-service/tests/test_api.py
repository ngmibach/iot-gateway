"""FastAPI device routes — TestClient with mocked actions/registry SSH."""

from __future__ import annotations

import tempfile
import time
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
from certs.rotate import DeviceReissue, RotateCAResult, RotateServerResult
from registry.registry import Registry


class _FakeSSH:
    """Minimal stand-in; playbooks are mocked so methods are unused."""

    pass


def _register_ok(_ssh: Any = None, **kwargs: Any) -> RegisterResult:
    user_id = kwargs.get("user_id")
    return RegisterResult(
        ok=True,
        status="ok",
        message="device registered",
        details={
            "user_id": user_id,
            "ip": kwargs.get("ip"),
            "kafka_topic": f"sensor.{user_id}",
            "kafka_retention_bytes": 1 * 1024**3,
            "kafka_capacity": {
                "total_storage_bytes": 10 * 1024**3,
                "topic_retention_bytes": 1 * 1024**3,
                "safety_ratio": 0.7,
                "budget_bytes": int(10 * 1024**3 * 0.7),
                "max_sensors": 7,
                "registered_sensors": 1,
                "remaining_slots": 6,
            },
        },
        cert_bundle=b"PK\x03\x04fake-zip",
        cert_fingerprint="ab" * 32,
        cert_expires_at="2030-01-01T00:00:00+00:00",
    )


def _register_capacity_full(_ssh: Any = None, **kwargs: Any) -> RegisterResult:
    return RegisterResult(
        ok=False,
        status="failed",
        message=(
            "gateway Kafka capacity full: 7/7 sensors "
            "(topic cap 1 bytes, disk 10 bytes, safety 70%)"
        ),
        details={
            "user_id": kwargs.get("user_id"),
            "ip": kwargs.get("ip"),
            "kafka_capacity": {
                "max_sensors": 7,
                "registered_sensors": 7,
                "topic_retention_bytes": 1,
                "total_storage_bytes": 10,
            },
        },
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
            install_root="/opt/iot-gateway-agent",
            fingerprint="fp-test",
        )
        self.settings = Settings(
            host="127.0.0.1",
            port=9137,
            data_dir=Path(self._tmp.name),
            registry_path=db,
            ca_passphrase="test-ca-secret",
            api_token=None,
            fake_cert_renewer_enabled=False,
        )
        self.cache = CertBundleCache(ttl_s=60)

        @contextmanager
        def open_ssh(_gw: dict[str, Any]) -> Iterator[_FakeSSH]:
            yield _FakeSSH()

        self.open_ssh = open_ssh
        self.app = create_app(
            settings=self.settings,
            registry=self.registry,
            open_ssh=open_ssh,
            cert_cache=self.cache,
            start_fake_cert_renewer=False,
        )
        self.client = TestClient(self.app)

    def _client_with_token(self, token: str = "secret-token") -> TestClient:
        settings = Settings(
            host="127.0.0.1",
            port=9137,
            data_dir=Path(self._tmp.name),
            registry_path=Path(self._tmp.name) / "registry.sqlite",
            api_token=token,
            ca_passphrase="test-ca-secret",
            fake_cert_renewer_enabled=False,
        )
        app = create_app(
            settings=settings,
            registry=self.registry,
            open_ssh=self.open_ssh,
            cert_cache=self.cache,
            start_fake_cert_renewer=False,
        )
        return TestClient(app)

    def test_health(self) -> None:
        r = self.client.get("/health")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["status"], "ok")
        self.assertEqual(self.client.get("/api/v1/health").status_code, 404)

    def test_list_gateways_node_instance(self) -> None:
        r = self.client.get("/api/v1/gateways")
        self.assertEqual(r.status_code, 200)
        rows = r.json()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["id"], "gw1")
        self.assertEqual(rows[0]["node_instance"], "gateway")

    def test_list_devices_is_fake_flag_and_filter(self) -> None:
        self.registry.upsert_device(
            "gw1",
            "real1",
            ip="10.0.0.2",
            meta_json={"kafka_topic": "sensor.real1"},
        )
        self.registry.upsert_device(
            "gw1",
            "fake1",
            ip="10.255.0.2",
            meta_json={
                "kafka_topic": "sensor.fake1",
                "is_fake": True,
                "fake": {
                    "ip": "10.255.0.2",
                    "status": "running",
                    "send_interval_ms": 1000,
                },
            },
        )
        all_rows = self.client.get("/api/v1/gateways/gw1/devices")
        self.assertEqual(all_rows.status_code, 200)
        by_id = {d["id"]: d for d in all_rows.json()}
        self.assertFalse(by_id["real1"]["is_fake"])
        self.assertIsNone(by_id["real1"].get("fake"))
        self.assertTrue(by_id["fake1"]["is_fake"])
        self.assertEqual(by_id["fake1"]["fake"]["status"], "running")
        self.assertEqual(by_id["fake1"]["fake"]["ip"], "10.255.0.2")

        only_fake = self.client.get(
            "/api/v1/gateways/gw1/devices", params={"is_fake": "true"}
        )
        self.assertEqual(only_fake.status_code, 200)
        fake_ids = [d["id"] for d in only_fake.json()]
        self.assertEqual(fake_ids, ["fake1"])

        only_real = self.client.get(
            "/api/v1/gateways/gw1/devices", params={"is_fake": "false"}
        )
        self.assertEqual(only_real.status_code, 200)
        real_ids = [d["id"] for d in only_real.json()]
        self.assertEqual(real_ids, ["real1"])

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
        self.assertEqual(body["device"]["kafka_topic"], "sensor.sensor5")
        self.assertFalse(body["device"]["is_fake"])
        self.assertIsNone(body["device"].get("fake"))
        self.assertEqual(body["kafka_topic"], "sensor.sensor5")
        self.assertEqual(body["kafka_capacity"]["max_sensors"], 7)
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
        self.assertFalse(listed.json()[0]["is_fake"])

        token = body["cert_bundle_token"]
        dl = self.client.get(
            "/api/v1/gateways/gw1/devices/sensor5/cert-bundle",
            params={"token": token},
        )
        self.assertEqual(dl.status_code, 200)
        self.assertEqual(dl.content, b"PK\x03\x04fake-zip")
        self.assertIn("application/zip", dl.headers.get("content-type", ""))

        dl2 = self.client.get(
            "/api/v1/gateways/gw1/devices/sensor5/cert-bundle",
            params={"token": token},
        )
        self.assertEqual(dl2.status_code, 404)

    def test_cert_bundle_download_without_api_token_when_configured(self) -> None:
        """Browser-style GET with only ?token= must work even if IOTGW_API_TOKEN is set."""
        client = self._client_with_token("secret-token")
        with patch("api.devices.register_device", side_effect=_register_ok):
            r = client.post(
                "/api/v1/gateways/gw1/devices",
                json={
                    "user_id": "sensor9",
                    "password": "password123",
                    "ip": "10.0.0.9",
                },
                headers={"X-API-Token": "secret-token"},
            )
        self.assertEqual(r.status_code, 200, r.text)
        token = r.json()["cert_bundle_token"]
        # No API header — Streamlit link_button / browser download.
        dl = client.get(
            "/api/v1/gateways/gw1/devices/sensor9/cert-bundle",
            params={"token": token},
        )
        self.assertEqual(dl.status_code, 200, dl.text)
        self.assertEqual(dl.content, b"PK\x03\x04fake-zip")
        self.assertEqual(
            client.get(
                "/api/v1/gateways/gw1/devices/sensor9/cert-bundle",
                params={"token": token},
            ).status_code,
            404,
        )

    def test_cert_bundle_ttl_expiry(self) -> None:
        cache = CertBundleCache(ttl_s=1)
        tok = cache.put("gw1", "sensor1", b"blob")
        self.assertEqual(cache.pop(tok, gateway_id="gw1", device_id="sensor1"), b"blob")
        tok = cache.put("gw1", "sensor1", b"blob")
        time.sleep(1.1)
        self.assertIsNone(cache.pop(tok, gateway_id="gw1", device_id="sensor1"))

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

    def test_register_validation_400_bad_ip(self) -> None:
        with patch("api.devices.register_device", side_effect=_register_ok) as mocked:
            r = self.client.post(
                "/api/v1/gateways/gw1/devices",
                json={
                    "user_id": "sensor5",
                    "password": "password123",
                    "ip": "not-an-ip",
                },
            )
        self.assertEqual(r.status_code, 400, r.text)
        self.assertIn("IP", r.json()["detail"])
        mocked.assert_not_called()

    def test_register_validation_400_reserved_user(self) -> None:
        with patch("api.devices.register_device", side_effect=_register_ok) as mocked:
            r = self.client.post(
                "/api/v1/gateways/gw1/devices",
                json={
                    "user_id": "nodered",
                    "password": "password123",
                    "ip": "10.0.0.1",
                },
            )
        self.assertEqual(r.status_code, 400, r.text)
        mocked.assert_not_called()

    def test_register_rejects_multi_topic_list(self) -> None:
        with patch("api.devices.register_device", side_effect=_register_ok) as mocked:
            r = self.client.post(
                "/api/v1/gateways/gw1/devices",
                json={
                    "user_id": "sensor5",
                    "password": "password123",
                    "ip": "10.0.0.1",
                    "topic_read": ["a/+", "b/+"],
                },
            )
        self.assertEqual(r.status_code, 422)
        mocked.assert_not_called()

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

    def test_register_capacity_full_409(self) -> None:
        with patch(
            "api.devices.register_device", side_effect=_register_capacity_full
        ):
            r = self.client.post(
                "/api/v1/gateways/gw1/devices",
                json={
                    "user_id": "sensor_new",
                    "password": "password123",
                    "ip": "10.0.0.99",
                },
            )
        self.assertEqual(r.status_code, 409, r.text)
        detail = r.json()["detail"]
        self.assertIn("capacity full", detail["message"])
        self.assertEqual(detail["kafka_capacity"]["max_sensors"], 7)

    def test_get_kafka_capacity(self) -> None:
        from actions.kafka_capacity import CapacityPlan

        plan = CapacityPlan(
            total_storage_bytes=10,
            topic_retention_bytes=1,
            safety_ratio=0.7,
            budget_bytes=7,
            max_sensors=7,
            registered_sensors=2,
            remaining_slots=5,
        )
        with patch("api.devices.gateway_kafka_capacity", return_value=plan):
            r = self.client.get("/api/v1/gateways/gw1/kafka/capacity")
        self.assertEqual(r.status_code, 200, r.text)
        body = r.json()
        self.assertEqual(body["max_sensors"], 7)
        self.assertEqual(body["registered_sensors"], 2)
        self.assertEqual(body["remaining_slots"], 5)
        self.assertFalse(body["at_capacity"])

    def test_delete_device(self) -> None:
        self.registry.upsert_device("gw1", "sensor1", ip="10.0.0.2")
        with patch("api.devices.unregister_device", side_effect=_unregister_ok) as mocked:
            r = self.client.delete("/api/v1/gateways/gw1/devices/sensor1")
        self.assertEqual(r.status_code, 200, r.text)
        self.assertTrue(r.json()["ok"])
        mocked.assert_called_once()
        self.assertIsNone(self.registry.get_device("gw1", "sensor1"))

    def test_patch_device_monitor_only(self) -> None:
        self.registry.upsert_device(
            "gw1",
            "sensor1",
            ip="10.0.0.2",
            topics_rw=["sensors/sensor1/#"],
            monitor_enabled=1,
        )
        with patch("api.devices.register_device", side_effect=_register_ok) as mocked:
            r = self.client.patch(
                "/api/v1/gateways/gw1/devices/sensor1",
                json={"monitor_enabled": False},
            )
        self.assertEqual(r.status_code, 200, r.text)
        body = r.json()
        self.assertFalse(body["playbook"])
        self.assertFalse(body["device"]["monitor_enabled"])
        mocked.assert_not_called()
        row = self.registry.get_device("gw1", "sensor1")
        self.assertEqual(row["monitor_enabled"], 0)
        self.assertEqual(row["ip"], "10.0.0.2")

    def test_patch_device_ip_requires_password(self) -> None:
        self.registry.upsert_device("gw1", "sensor1", ip="10.0.0.2")
        with patch("api.devices.register_device", side_effect=_register_ok) as mocked:
            r = self.client.patch(
                "/api/v1/gateways/gw1/devices/sensor1",
                json={"ip": "10.0.0.9"},
            )
        self.assertEqual(r.status_code, 400, r.text)
        self.assertIn("password", r.json()["detail"].lower())
        mocked.assert_not_called()

    def test_patch_device_playbook_update(self) -> None:
        self.registry.upsert_device("gw1", "sensor1", ip="10.0.0.2", monitor_enabled=1)
        with patch("api.devices.register_device", side_effect=_register_ok) as mocked:
            r = self.client.patch(
                "/api/v1/gateways/gw1/devices/sensor1",
                json={
                    "ip": "10.0.0.9",
                    "password": "password123",
                    "topic_readwrite": "sensors/sensor1/#",
                    "monitor_enabled": True,
                },
            )
        self.assertEqual(r.status_code, 200, r.text)
        body = r.json()
        self.assertTrue(body["playbook"])
        self.assertEqual(body["device"]["ip"], "10.0.0.9")
        mocked.assert_called_once()

    def test_api_token_x_header_and_bearer(self) -> None:
        client = self._client_with_token("secret-token")
        self.assertEqual(client.get("/api/v1/gateways").status_code, 401)
        self.assertEqual(
            client.get(
                "/api/v1/gateways",
                headers={"X-API-Token": "secret-token"},
            ).status_code,
            200,
        )
        self.assertEqual(
            client.get(
                "/api/v1/gateways",
                headers={"Authorization": "Bearer secret-token"},
            ).status_code,
            200,
        )
        with patch("api.devices.register_device", side_effect=_register_ok):
            denied = client.post(
                "/api/v1/gateways/gw1/devices",
                json={
                    "user_id": "sensor5",
                    "password": "password123",
                    "ip": "10.0.0.1",
                },
            )
            ok = client.post(
                "/api/v1/gateways/gw1/devices",
                json={
                    "user_id": "sensor5",
                    "password": "password123",
                    "ip": "10.0.0.1",
                },
                headers={"Authorization": "Bearer secret-token"},
            )
        self.assertEqual(denied.status_code, 401)
        self.assertEqual(ok.status_code, 200, ok.text)
        self.assertEqual(client.get("/health").status_code, 200)

    def test_rotate_server_cert(self) -> None:
        def _ok(_ssh: Any = None, **kwargs: Any) -> RotateServerResult:
            return RotateServerResult(
                ok=True,
                status="ok",
                message="rotated",
                fingerprint_sha256="cd" * 32,
                details={"gateway_ip": kwargs.get("gateway_ip")},
            )

        with patch("api.actions.rotate_server_cert", side_effect=_ok) as mocked:
            r = self.client.post(
                "/api/v1/gateways/gw1/actions/rotate-server-cert",
                json={},
            )
        self.assertEqual(r.status_code, 200, r.text)
        body = r.json()
        self.assertTrue(body["ok"])
        self.assertEqual(body["gateway_ip"], "192.168.1.50")
        self.assertEqual(body["fingerprint_sha256"], "cd" * 32)
        mocked.assert_called_once()
        self.assertEqual(mocked.call_args.kwargs["gateway_ip"], "192.168.1.50")

    def test_rotate_server_requires_ip_when_host_not_ip(self) -> None:
        self.registry.upsert_gateway(
            id="gw-name",
            host="gateway.local",
            ssh_user="pi",
            install_root="/opt/iot-gateway-agent",
            fingerprint="fp2",
        )
        with patch("api.actions.rotate_server_cert") as mocked:
            r = self.client.post(
                "/api/v1/gateways/gw-name/actions/rotate-server-cert",
                json={},
            )
        self.assertEqual(r.status_code, 400, r.text)
        mocked.assert_not_called()

    def test_rotate_ca_break_glass_and_tokens(self) -> None:
        self.registry.upsert_device("gw1", "sensor1", ip="10.0.0.2")

        def _ok(_ssh: Any = None, **kwargs: Any) -> RotateCAResult:
            return RotateCAResult(
                ok=True,
                status="ok",
                message="ca rotated",
                devices=[
                    DeviceReissue(
                        device_id="sensor1",
                        client_key_pem=b"k",
                        client_crt_pem=b"c",
                        ca_crt_pem=b"ca",
                        cert_bundle=b"PK\x03\x04ca-zip",
                        fingerprint_sha256="ee" * 32,
                    )
                ],
            )

        with patch("api.actions.rotate_ca", side_effect=_ok) as mocked:
            denied = self.client.post(
                "/api/v1/gateways/gw1/actions/rotate-ca",
                json={"confirm_break_glass": False},
            )
            self.assertEqual(denied.status_code, 400)

            r = self.client.post(
                "/api/v1/gateways/gw1/actions/rotate-ca",
                json={"confirm_break_glass": True},
            )
        self.assertEqual(r.status_code, 200, r.text)
        body = r.json()
        self.assertTrue(body["ok"])
        self.assertTrue(body["redistribute"])
        self.assertEqual(len(body["devices"]), 1)
        token = body["devices"][0]["cert_bundle_token"]
        mocked.assert_called_once()
        self.assertTrue(mocked.call_args.kwargs["confirm_break_glass"])

        dl = self.client.get(
            "/api/v1/gateways/gw1/devices/sensor1/cert-bundle",
            params={"token": token},
        )
        self.assertEqual(dl.status_code, 200)
        self.assertEqual(dl.content, b"PK\x03\x04ca-zip")

    def test_rotate_ca_reload_failed_no_redistribute(self) -> None:
        def _reload_failed(_ssh: Any = None, **kwargs: Any) -> RotateCAResult:
            return RotateCAResult(
                ok=False,
                status="reload_failed",
                message="frontends stale",
                devices=[
                    DeviceReissue(
                        device_id="sensor1",
                        client_key_pem=b"k",
                        client_crt_pem=b"c",
                        ca_crt_pem=b"ca",
                        cert_bundle=b"PK\x03\x04hold",
                    )
                ],
            )

        with patch("api.actions.rotate_ca", side_effect=_reload_failed):
            r = self.client.post(
                "/api/v1/gateways/gw1/actions/rotate-ca",
                json={"confirm_break_glass": True, "gateway_ip": "192.168.1.50"},
            )
        self.assertEqual(r.status_code, 200, r.text)
        body = r.json()
        self.assertFalse(body["ok"])
        self.assertEqual(body["status"], "reload_failed")
        self.assertFalse(body["redistribute"])
        self.assertEqual(len(body["devices"]), 1)

    def test_discover_sensors(self) -> None:
        def _discover(_ssh: Any = None) -> dict[str, Any]:
            return {
                "hosts": [
                    {"ip": "192.168.1.60", "mac": "aa:bb:cc:dd:ee:ff", "state": "REACHABLE"},
                    {"ip": "192.168.1.61", "state": "STALE"},
                ],
                "gateway_ips": ["192.168.1.50"],
            }

        with patch("api.devices.discover_sensor_hosts", side_effect=_discover) as mocked:
            r = self.client.post("/api/v1/gateways/gw1/devices/discover")
        self.assertEqual(r.status_code, 200, r.text)
        body = r.json()
        self.assertEqual(len(body["hosts"]), 2)
        self.assertEqual(body["hosts"][0]["ip"], "192.168.1.60")
        self.assertEqual(body["gateway_ips"], ["192.168.1.50"])
        mocked.assert_called_once()

    def test_discover_sensors_unknown_gateway(self) -> None:
        with patch("api.devices.discover_sensor_hosts") as mocked:
            r = self.client.post("/api/v1/gateways/missing/devices/discover")
        self.assertEqual(r.status_code, 404)
        mocked.assert_not_called()

    def test_reissue_cert(self) -> None:
        self.registry.upsert_device("gw1", "sensor1", ip="10.0.0.2")

        def _reissue(_ssh: Any = None, **kwargs: Any) -> RegisterResult:
            return RegisterResult(
                ok=True,
                status="ok",
                message="client certificate reissued",
                details={"user_id": kwargs.get("user_id")},
                cert_bundle=b"PK\x03\x04reissue-zip",
                cert_fingerprint="ff" * 32,
                cert_expires_at="2031-01-01T00:00:00+00:00",
            )

        with patch("api.devices.reissue_device_cert", side_effect=_reissue) as mocked:
            r = self.client.post(
                "/api/v1/gateways/gw1/devices/sensor1/reissue-cert",
                json={},
            )
        self.assertEqual(r.status_code, 200, r.text)
        body = r.json()
        self.assertEqual(body["device"]["id"], "sensor1")
        self.assertEqual(body["device"]["cert_fingerprint"], "ff" * 32)
        self.assertIsNotNone(body["cert_bundle_token"])
        mocked.assert_called_once()
        self.assertEqual(mocked.call_args.kwargs["user_id"], "sensor1")
        self.assertEqual(mocked.call_args.kwargs["ca_passphrase"], "test-ca-secret")

        token = body["cert_bundle_token"]
        dl = self.client.get(
            "/api/v1/gateways/gw1/devices/sensor1/cert-bundle",
            params={"token": token},
        )
        self.assertEqual(dl.status_code, 200)
        self.assertEqual(dl.content, b"PK\x03\x04reissue-zip")

    def test_reissue_cert_unknown_device(self) -> None:
        with patch("api.devices.reissue_device_cert") as mocked:
            r = self.client.post(
                "/api/v1/gateways/gw1/devices/missing/reissue-cert",
                json={},
            )
        self.assertEqual(r.status_code, 404)
        mocked.assert_not_called()

    def _seed_fake(self, device_id: str = "fake1", ip: str = "10.255.0.2") -> None:
        self.registry.upsert_device(
            "gw1",
            device_id,
            ip=ip,
            topics_rw=["sensors/fake1/#"],
            meta_json={
                "is_fake": True,
                "kafka_topic": f"sensor.{device_id}",
                "fake": {
                    "ip": ip,
                    "netns": f"iotgw-fake-{device_id}",
                    "unit": f"iotgw-fake@{device_id}",
                    "bridge": "iotgw-fake",
                    "status": "running",
                    "send_interval_ms": 1000,
                    "topic": f"sensors/{device_id}/process",
                    "behaviors": {
                        "omit_client_cert": False,
                        "wrong_client_cert": False,
                        "skip_encryption": False,
                        "bad_encryption": False,
                        "wrong_password": False,
                        "wrong_topic": False,
                    },
                },
            },
        )

    def test_create_fake_device_happy_path(self) -> None:
        from actions.fake_sensors import FakeAllocation, FakePlaybookResult

        alloc = FakeAllocation(
            device_id="fake1",
            ip="10.255.0.2",
            host_num=2,
            host_if="vf2",
            ns_if="vn2",
            netns="iotgw-fake-fake1",
            unit="iotgw-fake@fake1",
        )

        def _register(_ssh: Any = None, **kwargs: Any) -> RegisterResult:
            out = _register_ok(_ssh, **kwargs)
            out.client_key_pem = b"-----BEGIN PRIVATE KEY-----\nK\n-----END PRIVATE KEY-----\n"
            out.client_crt_pem = b"-----BEGIN CERTIFICATE-----\nC\n-----END CERTIFICATE-----\n"
            out.ca_crt_pem = b"-----BEGIN CERTIFICATE-----\nCA\n-----END CERTIFICATE-----\n"
            return out

        with (
            patch(
                "api.devices.ensure_fake_runtime",
                return_value=FakePlaybookResult(ok=True, message="runtime"),
            ),
            patch(
                "api.devices.create_netns",
                return_value=FakePlaybookResult(
                    ok=True,
                    message="netns",
                    details={"allocation": alloc.__dict__},
                ),
            ) as netns,
            patch("api.devices.register_device", side_effect=_register) as reg,
            patch(
                "api.devices.install_fake_files",
                return_value=FakePlaybookResult(ok=True, message="files"),
            ) as inst,
            patch(
                "api.devices.stop_fake_unit",
                return_value=FakePlaybookResult(ok=True, message="stopped"),
            ) as stop,
            patch("api.devices.teardown_fake") as torn,
        ):
            r = self.client.post(
                "/api/v1/gateways/gw1/devices/fake",
                json={
                    "user_id": "fake1",
                    "password": "hunter2xx",
                    "send_interval_ms": 500,
                    "payload": {"temp": 21},
                },
            )
        self.assertEqual(r.status_code, 200, r.text)
        body = r.json()
        self.assertTrue(body["device"]["is_fake"])
        self.assertEqual(body["device"]["ip"], "10.255.0.2")
        self.assertEqual(body["device"]["fake"]["ip"], "10.255.0.2")
        self.assertEqual(body["device"]["fake"]["status"], "stopped")
        self.assertEqual(body["device"]["fake"]["send_interval_ms"], 500)
        self.assertEqual(body["kafka_topic"], "sensor.fake1")
        # Fake certs are app-managed — no operator download token.
        self.assertIsNone(body.get("cert_bundle_token"))
        self.assertIn("stopped", (body.get("message") or "").lower())
        reg.assert_called_once()
        self.assertEqual(reg.call_args.kwargs["ip"], "10.255.0.2")
        inst.assert_called_once()
        stop.assert_called_once()
        netns.assert_called_once()
        torn.assert_not_called()

    def test_create_fake_conflicts_with_real_device(self) -> None:
        self.registry.upsert_device("gw1", "sensor1", ip="10.0.0.2")
        r = self.client.post(
            "/api/v1/gateways/gw1/devices/fake",
            json={"user_id": "sensor1", "password": "hunter2xx"},
        )
        self.assertEqual(r.status_code, 409, r.text)

    def test_get_patch_start_stop_fake(self) -> None:
        from actions.fake_sensors import FakePlaybookResult

        self._seed_fake()
        g = self.client.get("/api/v1/gateways/gw1/devices/fake1/fake")
        self.assertEqual(g.status_code, 200, g.text)
        self.assertEqual(g.json()["ip"], "10.255.0.2")
        self.assertEqual(g.json()["status"], "running")

        with (
            patch(
                "api.devices.update_fake_config",
                return_value=FakePlaybookResult(ok=True),
            ) as upd,
            patch(
                "api.devices.restart_fake_unit",
                return_value=FakePlaybookResult(ok=True),
            ),
        ):
            p = self.client.patch(
                "/api/v1/gateways/gw1/devices/fake1/fake",
                json={
                    "send_interval_ms": 2000,
                    "behaviors": {"omit_client_cert": True},
                },
            )
        self.assertEqual(p.status_code, 200, p.text)
        self.assertEqual(p.json()["device"]["fake"]["send_interval_ms"], 2000)
        self.assertTrue(p.json()["device"]["fake"]["behaviors"]["omit_client_cert"])
        upd.assert_called_once()

        with patch(
            "api.devices.enable_and_start_unit",
            return_value=FakePlaybookResult(ok=True),
        ):
            s = self.client.post(
                "/api/v1/gateways/gw1/devices/fake1/fake/start", json={}
            )
        self.assertEqual(s.status_code, 200, s.text)
        self.assertEqual(s.json()["device"]["fake"]["status"], "running")

        with patch(
            "api.devices.stop_fake_unit",
            return_value=FakePlaybookResult(ok=True),
        ):
            st = self.client.post(
                "/api/v1/gateways/gw1/devices/fake1/fake/stop", json={}
            )
        self.assertEqual(st.status_code, 200, st.text)
        self.assertEqual(st.json()["device"]["fake"]["status"], "stopped")

    def test_patch_fake_keeps_registry_when_restart_fails(self) -> None:
        from actions.fake_sensors import FakePlaybookResult

        self._seed_fake()
        with (
            patch(
                "api.devices.update_fake_config",
                return_value=FakePlaybookResult(ok=True),
            ),
            patch(
                "api.devices.restart_fake_unit",
                return_value=FakePlaybookResult(
                    ok=False, status="failed", message="unit missing"
                ),
            ),
        ):
            p = self.client.patch(
                "/api/v1/gateways/gw1/devices/fake1/fake",
                json={
                    "send_interval_ms": 3333,
                    "behaviors": {"skip_encryption": True},
                },
            )
        self.assertEqual(p.status_code, 502, p.text)
        self.assertIn("Config saved", p.json()["detail"])
        import json as _json

        row = self.registry.get_device("gw1", "fake1")
        assert row is not None
        raw_meta = row["meta_json"]
        meta = (
            raw_meta
            if isinstance(raw_meta, dict)
            else _json.loads(raw_meta or "{}")
        )
        fake = meta.get("fake") or {}
        self.assertEqual(fake.get("send_interval_ms"), 3333)
        self.assertTrue(fake.get("behaviors", {}).get("skip_encryption"))
        self.assertEqual(fake.get("status"), "error")

    def test_feed_cert_rejects_real_device(self) -> None:
        self.registry.upsert_device("gw1", "sensor1", ip="10.0.0.2")
        r = self.client.post(
            "/api/v1/gateways/gw1/devices/sensor1/fake/feed-cert",
            json={},
        )
        self.assertEqual(r.status_code, 400, r.text)

    def test_feed_cert_reissues_and_feeds(self) -> None:
        from actions.fake_sensors import FakePlaybookResult

        self._seed_fake()

        def _reissue(_ssh: Any = None, **kwargs: Any) -> RegisterResult:
            return RegisterResult(
                ok=True,
                status="ok",
                message="reissued",
                details={"user_id": kwargs.get("user_id")},
                cert_bundle=b"PK\x03\x04fed-zip",
                cert_fingerprint="aa" * 32,
                cert_expires_at="2032-01-01T00:00:00+00:00",
                ca_crt_pem=b"CA",
                client_crt_pem=b"CRT",
                client_key_pem=b"KEY",
            )

        with (
            patch("api.devices.reissue_device_cert", side_effect=_reissue) as reiss,
            patch(
                "api.devices.feed_fake_certs",
                return_value=FakePlaybookResult(ok=True, message="fed"),
            ) as fed,
        ):
            r = self.client.post(
                "/api/v1/gateways/gw1/devices/fake1/fake/feed-cert",
                json={"reissue": True},
            )
        self.assertEqual(r.status_code, 200, r.text)
        body = r.json()
        self.assertEqual(body["device"]["cert_fingerprint"], "aa" * 32)
        self.assertEqual(body["device"]["fake"]["cert_feed_fingerprint"], "aa" * 32)
        self.assertIsNotNone(body["device"]["fake"]["cert_fed_at"])
        reiss.assert_called_once()
        fed.assert_called_once()

    def test_reissue_fake_also_feeds(self) -> None:
        from actions.fake_sensors import FakePlaybookResult

        self._seed_fake()

        def _reissue(_ssh: Any = None, **kwargs: Any) -> RegisterResult:
            return RegisterResult(
                ok=True,
                status="ok",
                message="reissued",
                cert_bundle=b"PK\x03\x04reissue-fake",
                cert_fingerprint="bb" * 32,
                cert_expires_at="2032-06-01T00:00:00+00:00",
                ca_crt_pem=b"CA",
                client_crt_pem=b"CRT",
                client_key_pem=b"KEY",
            )

        with (
            patch("api.devices.reissue_device_cert", side_effect=_reissue),
            patch(
                "api.devices.feed_fake_certs",
                return_value=FakePlaybookResult(ok=True),
            ) as fed,
        ):
            r = self.client.post(
                "/api/v1/gateways/gw1/devices/fake1/reissue-cert",
                json={},
            )
        self.assertEqual(r.status_code, 200, r.text)
        self.assertIn("fed", r.json()["message"].lower())
        self.assertEqual(r.json()["device"]["fake"]["cert_feed_fingerprint"], "bb" * 32)
        fed.assert_called_once()

    def test_delete_fake_tears_down_runtime(self) -> None:
        from actions.fake_sensors import FakePlaybookResult

        self._seed_fake()
        with (
            patch(
                "api.devices.teardown_fake",
                return_value=FakePlaybookResult(ok=True, message="torn"),
            ) as torn,
            patch(
                "api.devices.unregister_device", side_effect=_unregister_ok
            ) as unreg,
        ):
            r = self.client.delete("/api/v1/gateways/gw1/devices/fake1")
        self.assertEqual(r.status_code, 200, r.text)
        torn.assert_called_once()
        unreg.assert_called_once()
        self.assertIsNone(self.registry.get_device("gw1", "fake1"))

    def test_delete_real_skips_teardown(self) -> None:
        self.registry.upsert_device("gw1", "sensor1", ip="10.0.0.2")
        with (
            patch("api.devices.teardown_fake") as torn,
            patch(
                "api.devices.unregister_device", side_effect=_unregister_ok
            ),
        ):
            r = self.client.delete("/api/v1/gateways/gw1/devices/sensor1")
        self.assertEqual(r.status_code, 200, r.text)
        torn.assert_not_called()

    def test_rotate_ca_feeds_fake_devices(self) -> None:
        from actions.fake_sensors import FakePlaybookResult

        self._seed_fake()
        self.registry.upsert_device("gw1", "sensor1", ip="10.0.0.2")

        def _ok(_ssh: Any = None, **kwargs: Any) -> RotateCAResult:
            return RotateCAResult(
                ok=True,
                status="ok",
                message="CA rotated",
                ca_crt_pem=b"CA",
                server_crt_pem=b"SRV",
                devices=[
                    DeviceReissue(
                        device_id="fake1",
                        client_key_pem=b"KEY",
                        client_crt_pem=b"CRT",
                        ca_crt_pem=b"CA",
                        cert_bundle=b"PK\x03\x04fake",
                        fingerprint_sha256="cc" * 32,
                    ),
                    DeviceReissue(
                        device_id="sensor1",
                        client_key_pem=b"KEY2",
                        client_crt_pem=b"CRT2",
                        ca_crt_pem=b"CA",
                        cert_bundle=b"PK\x03\x04real",
                        fingerprint_sha256="dd" * 32,
                    ),
                ],
            )

        with (
            patch("api.actions.rotate_ca", side_effect=_ok),
            patch(
                "api.actions.feed_and_record_certs",
                return_value=(FakePlaybookResult(ok=True), {}),
            ) as fed,
        ):
            r = self.client.post(
                "/api/v1/gateways/gw1/actions/rotate-ca",
                json={"confirm_break_glass": True},
            )
        self.assertEqual(r.status_code, 200, r.text)
        # Only the fake device is fed.
        self.assertEqual(fed.call_count, 1)
        self.assertEqual(fed.call_args.kwargs["device_id"], "fake1")


if __name__ == "__main__":
    unittest.main()

