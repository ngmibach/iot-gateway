"""Tests for /api/v1/query/* proxies, summaries, and monitor_enabled filter."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from typing import Any, Iterator
from unittest.mock import patch

from fastapi.testclient import TestClient

from api.app import create_app
from api import queries as Q
from api.settings import Settings
from registry.registry import Registry


class _FakeSSH:
    pass


class QueryApiTests(unittest.TestCase):
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
        self.registry.upsert_device(
            gateway_id="gw1",
            id="sensor_a",
            ip="10.0.0.1",
            monitor_enabled=1,
        )
        self.registry.upsert_device(
            gateway_id="gw1",
            id="sensor_b",
            ip="10.0.0.2",
            monitor_enabled=0,
        )
        self.settings = Settings(
            host="127.0.0.1",
            port=9137,
            data_dir=Path(self._tmp.name),
            registry_path=db,
            loki_url="http://loki.test:3100",
            prometheus_url="http://prom.test:9090",
        )

        from contextlib import contextmanager

        @contextmanager
        def open_ssh(_gw: dict[str, Any]) -> Iterator[_FakeSSH]:
            yield _FakeSSH()

        self.app = create_app(
            settings=self.settings,
            registry=self.registry,
            open_ssh=open_ssh,
        )
        self.client = TestClient(self.app)

    def test_golden_expressions_match_streamlit_shapes(self) -> None:
        """Spot-check expressions still contain the Streamlit dashboard markers."""
        self.assertIn('event_type="sensor_data"', Q.GATEWAY_TOTAL_SENSOR_MSGS)
        self.assertIn("iot-nodered", Q.GATEWAY_TOTAL_SENSOR_MSGS)
        self.assertIn("ids-alerts", Q.GATEWAY_IDS_ALERTS)
        self.assertIn("mqtt_connected_sensor", Q.GATEWAY_CONNECTED_SENSORS)
        self.assertIn("node_cpu_seconds_total", Q.RASPI_CPU_USAGE)
        self.assertIn("$node", Q.RASPI_MEM_TOTAL)
        self.assertIn("temperatureZone1", Q.SENSORS_TEMP_ZONE1)
        self.assertIn("sinteringStage", Q.SENSORS_STAGE)
        prepped = Q.prep_loki(Q.GATEWAY_TOTAL_SENSOR_MSGS, duration="15m")
        self.assertIn("[15m]", prepped)
        self.assertNotIn("{range}", prepped)
        self.assertIn('instance="gateway"', Q.prep_prom(Q.RASPI_UP))

    def test_filter_series_by_device(self) -> None:
        series = [
            {"metric": {"deviceId": "sensor_a"}, "values": [["1", "1"]]},
            {"metric": {"deviceId": "sensor_b"}, "values": [["1", "2"]]},
            {"metric": {"device_id": "sensor_a"}, "value": ["1", "3"]},
        ]
        out = Q.filter_series_by_device(series, allowed={"sensor_a"})
        self.assertEqual(len(out), 2)
        self.assertEqual(
            Q.filter_series_by_device(series, allowed=None),
            series,
        )

    def test_monitor_devices_filter(self) -> None:
        r = self.client.get("/api/v1/query/monitor-devices", params={"gateway_id": "gw1"})
        self.assertEqual(r.status_code, 200, r.text)
        body = r.json()
        self.assertTrue(body["filter_active"])
        self.assertEqual(body["device_ids"], ["sensor_a"])

        r2 = self.client.get(
            "/api/v1/query/monitor-devices",
            params={"gateway_id": "gw1", "show_all": True},
        )
        self.assertFalse(r2.json()["filter_active"])
        self.assertEqual(r2.json()["device_ids"], [])

    def test_query_loki_range_proxy(self) -> None:
        fake = {
            "status": "success",
            "data": {"resultType": "matrix", "result": []},
        }

        class _Resp:
            status_code = 200
            text = "{}"

            def json(self) -> dict:
                return fake

        class _Client:
            def __init__(self, *a: Any, **k: Any) -> None:
                pass

            def __enter__(self) -> "_Client":
                return self

            def __exit__(self, *a: Any) -> None:
                return None

            def get(self, url: str, params: dict | None = None) -> _Resp:
                self.url = url
                self.params = params
                return _Resp()

        with patch("api.query.httpx.Client", _Client) as _:
            # Re-patch by capturing instance via side effect
            captured: dict[str, Any] = {}

            class _Capturing(_Client):
                def get(self, url: str, params: dict | None = None) -> _Resp:
                    captured["url"] = url
                    captured["params"] = params
                    return _Resp()

            with patch("api.query.httpx.Client", _Capturing):
                r = self.client.get(
                    "/api/v1/query/loki",
                    params={
                        "query": '{job="x"}',
                        "start": "1",
                        "end": "2",
                        "limit": 10,
                    },
                )
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json()["status"], "success")
        self.assertIn("/loki/api/v1/query_range", captured["url"])
        self.assertEqual(captured["params"]["query"], '{job="x"}')

    def test_query_prometheus_instant_proxy(self) -> None:
        fake = {
            "status": "success",
            "data": {
                "resultType": "vector",
                "result": [{"metric": {}, "value": [1, "42"]}],
            },
        }
        captured: dict[str, Any] = {}

        class _Resp:
            status_code = 200
            text = "{}"

            def json(self) -> dict:
                return fake

        class _Client:
            def __init__(self, *a: Any, **k: Any) -> None:
                pass

            def __enter__(self) -> "_Client":
                return self

            def __exit__(self, *a: Any) -> None:
                return None

            def get(self, url: str, params: dict | None = None) -> _Resp:
                captured["url"] = url
                captured["params"] = params
                return _Resp()

        with patch("api.query.httpx.Client", _Client):
            r = self.client.get(
                "/api/v1/query/prometheus",
                params={"query": "up"},
            )
        self.assertEqual(r.status_code, 200)
        self.assertIn("/api/v1/query", captured["url"])
        self.assertNotIn("query_range", captured["url"])
        self.assertEqual(r.json()["data"]["result"][0]["value"][1], "42")

    def test_query_backend_error_502(self) -> None:
        class _Resp:
            status_code = 500
            text = "boom"

            def json(self) -> dict:
                return {}

        class _Client:
            def __init__(self, *a: Any, **k: Any) -> None:
                pass

            def __enter__(self) -> "_Client":
                return self

            def __exit__(self, *a: Any) -> None:
                return None

            def get(self, url: str, params: dict | None = None) -> _Resp:
                return _Resp()

        with patch("api.query.httpx.Client", _Client):
            r = self.client.get("/api/v1/query/prometheus", params={"query": "up"})
        self.assertEqual(r.status_code, 502)

    def test_summary_sensors_applies_monitor_enabled(self) -> None:
        """Sensors summary drops deviceIds not in monitor_enabled=1 set."""

        def fake_proxy(url: str, params: dict[str, Any]) -> Any:
            q = params.get("query", "")
            if "sinteringStage" in q or "label_format stage" in q:
                return {
                    "status": "success",
                    "data": {
                        "result": [
                            {
                                "metric": {"deviceId": "sensor_a", "stage": "heat"},
                                "values": [["1", "heat"]],
                            },
                            {
                                "metric": {"deviceId": "sensor_b", "stage": "cool"},
                                "values": [["1", "cool"]],
                            },
                        ]
                    },
                }
            # temperature / pressure series
            return {
                "status": "success",
                "data": {
                    "result": [
                        {
                            "metric": {"deviceId": "sensor_a"},
                            "values": [["1", "10"], ["2", "12"]],
                        },
                        {
                            "metric": {"deviceId": "sensor_b"},
                            "values": [["1", "99"]],
                        },
                    ]
                },
            }

        with patch("api.query._proxy_get", side_effect=fake_proxy):
            r = self.client.get(
                "/api/v1/query/summaries/sensors",
                params={"gateway_id": "gw1", "range": "1h"},
            )
        self.assertEqual(r.status_code, 200, r.text)
        body = r.json()
        self.assertTrue(body["filter_active"])
        self.assertEqual(body["monitored_device_ids"], ["sensor_a"])
        self.assertEqual([s["device_id"] for s in body["stages"]], ["sensor_a"])
        for row in body["temperatures"]:
            self.assertEqual(row["device_id"], "sensor_a")

        with patch("api.query._proxy_get", side_effect=fake_proxy):
            r2 = self.client.get(
                "/api/v1/query/summaries/sensors",
                params={"gateway_id": "gw1", "show_all": True},
            )
        self.assertFalse(r2.json()["filter_active"])
        self.assertEqual(len(r2.json()["stages"]), 2)

    def test_summary_gateway_scalars(self) -> None:
        def fake_proxy(url: str, params: dict[str, Any]) -> Any:
            q = str(params.get("query", ""))
            if "mqtt_connected_sensor" in q:
                return {
                    "status": "success",
                    "data": {
                        "result": [
                            {
                                "metric": {
                                    "device_id": "sensor_a",
                                    "client_id": "c1",
                                    "source_ip": "10.0.0.1",
                                },
                                "value": [1, "1"],
                            }
                        ]
                    },
                }
            if "allowed_ip_count" in q:
                return {
                    "status": "success",
                    "data": {"result": [{"metric": {}, "value": [1, "3"]}]},
                }
            # Loki scalars / delay
            if "unwrap delay" in q:
                return {
                    "status": "success",
                    "data": {
                        "result": [
                            {
                                "metric": {"deviceId": "sensor_a"},
                                "values": [["1", "0.01"], ["2", "0.02"]],
                            }
                        ]
                    },
                }
            # count / rate queries → single scalar
            return {
                "status": "success",
                "data": {"result": [{"metric": {}, "values": [["1", "5"]]}]},
            }

        with patch("api.query._proxy_get", side_effect=fake_proxy):
            r = self.client.get("/api/v1/query/summaries/gateway", params={"range": "1h"})
        self.assertEqual(r.status_code, 200, r.text)
        m = r.json()["metrics"]
        self.assertEqual(m["total_sensor_messages"], 5)
        self.assertEqual(m["allowed_ips"], 3)
        self.assertEqual(r.json()["connected_sensors"][0]["device_id"], "sensor_a")
        self.assertEqual(r.json()["delay_by_device"][0]["sparkline"][-1], 0.02)

    def test_summary_raspi(self) -> None:
        def fake_proxy(url: str, params: dict[str, Any]) -> Any:
            q = str(params.get("query", ""))
            if "query_range" in url or "rate(node_cpu" in q and "start" in (params or {}):
                return {
                    "status": "success",
                    "data": {
                        "result": [
                            {
                                "metric": {},
                                "values": [["1", "0.1"], ["2", "0.2"]],
                            }
                        ]
                    },
                }
            # Instant scalars — pick by expression fragment
            val = "1"
            if "MemTotal" in q and "MemAvailable" in q:
                val = "500000000"
            elif "MemTotal" in q:
                val = "1000000000"
            elif "count(count(node_cpu" in q and "idle" not in q:
                val = "4"
            elif "idle" in q:
                val = "1.5"
            elif "node_load1" in q:
                val = "0.5"
            elif "filesystem_avail" in q:
                val = "20000000000"
            elif "filesystem_size" in q:
                val = "64000000000"
            elif "container_last_seen" in q:
                val = "7"
            elif q.startswith("up"):
                val = "1"
            return {
                "status": "success",
                "data": {"result": [{"metric": {}, "value": [1, val]}]},
            }

        with patch("api.query._proxy_get", side_effect=fake_proxy):
            r = self.client.get("/api/v1/query/summaries/raspi")
        self.assertEqual(r.status_code, 200, r.text)
        body = r.json()
        self.assertTrue(body["up"])
        self.assertEqual(body["metrics"]["cpu_cores"], 4)
        self.assertEqual(body["metrics"]["active_containers"], 7)
        self.assertEqual(body["metrics"]["mem_used_pct"], 50.0)

    def test_query_requires_token_when_configured(self) -> None:
        settings = Settings(
            host="127.0.0.1",
            port=9137,
            data_dir=Path(self._tmp.name),
            registry_path=Path(self._tmp.name) / "registry.sqlite",
            api_token="secret",
            loki_url="http://loki.test:3100",
            prometheus_url="http://prom.test:9090",
        )
        from contextlib import contextmanager

        @contextmanager
        def open_ssh(_gw: dict[str, Any]) -> Iterator[_FakeSSH]:
            yield _FakeSSH()

        app = create_app(
            settings=settings, registry=self.registry, open_ssh=open_ssh
        )
        client = TestClient(app)
        r = client.get("/api/v1/query/monitor-devices")
        self.assertEqual(r.status_code, 401)
        r2 = client.get(
            "/api/v1/query/monitor-devices",
            headers={"X-API-Token": "secret"},
        )
        self.assertEqual(r2.status_code, 200)


if __name__ == "__main__":
    unittest.main()
