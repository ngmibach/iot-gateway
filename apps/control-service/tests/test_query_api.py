"""Tests for /api/v1/query/* proxies, summaries, and monitor_enabled filter."""

from __future__ import annotations

import tempfile
import unittest
from contextlib import contextmanager
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
            install_root="/opt/iot-gateway-agent",
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

        @contextmanager
        def open_ssh(_gw: dict[str, Any]) -> Iterator[_FakeSSH]:
            yield _FakeSSH()

        self.open_ssh = open_ssh
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
        self.assertIn("iotgw_denied_publishes_total", Q.GATEWAY_DENIED_PROM)
        self.assertIn("iotgw_ids_detections_total", Q.GATEWAY_IDS_PROM)
        self.assertIn("iotgw_device_messages_total", Q.GATEWAY_MSGS_BY_DEVICE_PROM)
        self.assertIn("iotgw_kafka_up", Q.RASPI_KAFKA_UP)
        self.assertIn("iotgw_kafka_produce_total", Q.RASPI_KAFKA_PRODUCE_PER_MIN)
        self.assertIn("mqtt_connected_sensor", Q.GATEWAY_CONNECTED_SENSORS)
        self.assertIn("node_cpu_seconds_total", Q.RASPI_CPU_USAGE)
        self.assertIn("$node", Q.RASPI_MEM_TOTAL)
        self.assertIn("temperatureZone1", Q.SENSORS_TEMP_ZONE1)
        self.assertIn("sinteringStage", Q.SENSORS_STAGE)
        prepped = Q.prep_loki(Q.GATEWAY_TOTAL_SENSOR_MSGS, duration="15m")
        self.assertIn("[15m]", prepped)
        self.assertNotIn("{range}", prepped)
        prepped_prom = Q.prep_prom(Q.RASPI_UP)
        self.assertIn('instance="gateway"', prepped_prom)
        self.assertIn('job="iot-gateway-agent"', prepped_prom)

    def test_filter_series_by_device(self) -> None:
        series = [
            {"metric": {"deviceId": "sensor_a"}, "values": [["1", "1"]]},
            {"metric": {"deviceId": "sensor_b"}, "values": [["1", "2"]]},
            {"metric": {"device_id": "sensor_a"}, "value": ["1", "3"]},
            {"metric": {"job": "x"}, "values": [["1", "9"]]},  # unlabeled → drop
        ]
        out = Q.filter_series_by_device(series, allowed={"sensor_a"})
        self.assertEqual(len(out), 2)
        self.assertEqual(
            Q.filter_series_by_device(series, allowed=None),
            series,
        )

    def test_sparkline_floats_skips_bad(self) -> None:
        self.assertEqual(
            Q.sparkline_floats([["1", "1.5"], ["2", "nope"], ["3", "2"]]),
            [1.5, 2.0],
        )

    def test_sensors_filter_empty_registry_shows_all(self) -> None:
        db = Path(self._tmp.name) / "empty.sqlite"
        reg = Registry(str(db))
        reg.upsert_gateway(
            id="gw_empty",
            host="10.0.0.1",
            ssh_user="pi",
            install_root="/opt",
            fingerprint="fp",
        )
        app = create_app(
            settings=Settings(
                host="127.0.0.1",
                port=9137,
                data_dir=Path(self._tmp.name),
                registry_path=db,
                loki_url="http://loki.test:3100",
                prometheus_url="http://prom.test:9090",
            ),
            registry=reg,
            open_ssh=self.open_ssh,
        )
        client = TestClient(app)

        def fake_proxy(url: str, params: dict[str, Any]) -> Any:
            return {
                "status": "success",
                "data": {
                    "result": [
                        {
                            "metric": {"deviceId": "raw1", "stage": "x"},
                            "values": [["1", "x"]],
                        }
                    ]
                },
            }

        with patch("api.query._proxy_get", side_effect=fake_proxy):
            r = client.get(
                "/api/v1/query/summaries/sensors",
                params={"gateway_id": "gw_empty"},
            )
        self.assertEqual(r.status_code, 200, r.text)
        self.assertFalse(r.json()["filter_active"])
        self.assertEqual(len(r.json()["stages"]), 1)

    def test_sensors_filter_all_disabled_empty_view(self) -> None:
        self.registry.upsert_device(
            gateway_id="gw1", id="sensor_a", monitor_enabled=0
        )

        def fake_proxy(url: str, params: dict[str, Any]) -> Any:
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

        with patch("api.query._proxy_get", side_effect=fake_proxy):
            r = self.client.get(
                "/api/v1/query/summaries/sensors",
                params={"gateway_id": "gw1"},
            )
        self.assertEqual(r.status_code, 200, r.text)
        body = r.json()
        self.assertTrue(body["filter_active"])
        self.assertEqual(body["monitored_device_ids"], [])
        self.assertEqual(body["stages"], [])

    def test_sensors_bad_gateway_404(self) -> None:
        r = self.client.get(
            "/api/v1/query/summaries/sensors",
            params={"gateway_id": "missing"},
        )
        self.assertEqual(r.status_code, 404)

    def test_query_loki_range_proxy(self) -> None:
        fake = {
            "status": "success",
            "data": {"resultType": "matrix", "result": []},
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

    def test_summary_gateway_soft_fail(self) -> None:
        def boom(url: str, params: dict[str, Any]) -> Any:
            from fastapi import HTTPException

            raise HTTPException(status_code=502, detail="down")

        with patch("api.query._proxy_get", side_effect=boom):
            r = self.client.get(
                "/api/v1/query/summaries/gateway", params={"gateway_id": "gw1"}
            )
        self.assertEqual(r.status_code, 200, r.text)
        body = r.json()
        self.assertEqual(body["metrics"]["total_sensor_messages"], 0)
        self.assertIn("messages_per_sec", body["metrics"])
        self.assertTrue(body["warnings"])
        # Registry sensors still listed when backends are down.
        ids = {s["device_id"] for s in body["connected_sensors"]}
        self.assertEqual(ids, {"sensor_a", "sensor_b"})
        for s in body["connected_sensors"]:
            self.assertIn("is_fake", s)
            self.assertFalse(s["is_fake"])

    def test_summary_gateway_catalog_sync_scrubs_ssh_keys(self) -> None:
        """Activities warnings must never include OpenSSH key bodies."""
        leaked = "AAAAC3NzaC1lZDI1NTE5AAAAICGmoZVh+fAh2Lm6O/yyMx3c98oO6pdT5aW2C96IvM6h"

        @contextmanager
        def bad_ssh(_gw: dict[str, Any]) -> Iterator[_FakeSSH]:
            raise RuntimeError(
                f"SSH host key mismatch for 172.20.10.2: got {leaked}"
            )
            yield _FakeSSH()  # pragma: no cover

        self.app = create_app(
            settings=self.settings,
            registry=self.registry,
            open_ssh=bad_ssh,
        )
        client = TestClient(self.app)

        def empty_proxy(url: str, params: dict[str, Any]) -> Any:
            return {"status": "success", "data": {"result": []}}

        with patch("api.query._proxy_get", side_effect=empty_proxy):
            r = client.get(
                "/api/v1/query/summaries/gateway", params={"gateway_id": "gw1"}
            )
        self.assertEqual(r.status_code, 200, r.text)
        warnings = r.json().get("warnings") or []
        joined = "\n".join(warnings)
        self.assertTrue(
            any(w.startswith("kafka_catalog_sync:") for w in warnings),
            warnings,
        )
        self.assertNotIn(leaked, joined)
        self.assertNotIn("AAAA", joined)

    def test_summary_gateway_scalars(self) -> None:
        self.registry.upsert_device(
            gateway_id="gw1",
            id="sensor_a",
            ip="10.0.0.1",
            monitor_enabled=1,
            meta_json={
                "kafka_topic": "sensor.sensor_a",
                "kafka_retention_bytes": 1073741824,
            },
        )

        def fake_proxy(url: str, params: dict[str, Any]) -> Any:
            q = str(params.get("query", ""))
            if "iotgw_decrypt_messages_total" in q and "rate(" in q:
                return {
                    "status": "success",
                    "data": {"result": [{"metric": {}, "value": [1, "0.5"]}]},
                }
            if "iotgw_decrypt_messages_total" in q:
                return {
                    "status": "success",
                    "data": {"result": [{"metric": {}, "value": [1, "42"]}]},
                }
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
            if "unwrap delay" in q:
                return {
                    "status": "success",
                    "data": {
                        "result": [
                            {
                                "metric": {"deviceId": "sensor_a"},
                                "values": [["1", "0.01"], ["2", "bad"], ["3", "0.02"]],
                            }
                        ]
                    },
                }
            return {
                "status": "success",
                "data": {"result": [{"metric": {}, "values": [["1", "5"]]}]},
            }

        with patch("api.query._proxy_get", side_effect=fake_proxy):
            r = self.client.get(
                "/api/v1/query/summaries/gateway",
                params={"range": "1h", "gateway_id": "gw1"},
            )
        self.assertEqual(r.status_code, 200, r.text)
        body = r.json()
        m = body["metrics"]
        self.assertEqual(m["total_sensor_messages"], 42)
        self.assertEqual(m["messages_per_sec"], 0.5)
        self.assertEqual(m["allowed_ips"], 3)
        self.assertEqual(body["gateway_id"], "gw1")
        by_id = {s["device_id"]: s for s in body["connected_sensors"]}
        self.assertIn("sensor_a", by_id)
        self.assertEqual(by_id["sensor_a"]["kafka_topic"], "sensor.sensor_a")
        self.assertEqual(by_id["sensor_a"]["kafka_retention_bytes"], 1073741824)
        self.assertEqual(by_id["sensor_a"]["client_id"], "c1")
        self.assertFalse(by_id["sensor_a"]["is_fake"])
        self.assertEqual(body["delay_by_device"][0]["sparkline"], [0.01, 0.02])
        self.assertIn("delay", body["charts"])

    def test_summary_gateway_connected_sensors_is_fake(self) -> None:
        """Activities connected_sensors carries registry is_fake for Fake/Real UI."""
        self.registry.upsert_device(
            gateway_id="gw1",
            id="fake1",
            ip="10.255.0.2",
            monitor_enabled=1,
            meta_json={
                "is_fake": True,
                "kafka_topic": "sensor.fake1",
                "fake": {"status": "running", "ip": "10.255.0.2"},
            },
        )

        def empty_proxy(url: str, params: dict[str, Any]) -> Any:
            return {"status": "success", "data": {"result": []}}

        with patch("api.query._proxy_get", side_effect=empty_proxy):
            r = self.client.get(
                "/api/v1/query/summaries/gateway", params={"gateway_id": "gw1"}
            )
        self.assertEqual(r.status_code, 200, r.text)
        by_id = {s["device_id"]: s for s in r.json()["connected_sensors"]}
        self.assertTrue(by_id["fake1"]["is_fake"])
        self.assertFalse(by_id["sensor_a"]["is_fake"])
        self.assertFalse(by_id["sensor_b"]["is_fake"])

    def test_summary_raspi(self) -> None:
        def fake_proxy(url: str, params: dict[str, Any]) -> Any:
            q = str(params.get("query", ""))
            if "query_range" in url:
                return {
                    "status": "success",
                    "data": {
                        "result": [
                            {
                                "metric": {},
                                "values": [["1", "10"], ["2", "20"]],
                            }
                        ]
                    },
                }
            if "iotgw_app_cpu_seconds_total" in q:
                return {
                    "status": "success",
                    "data": {
                        "result": [
                            {
                                "metric": {"app": "agent"},
                                "value": [1, "0.12"],
                            },
                            {
                                "metric": {"app": "mqtt"},
                                "value": [1, "0.04"],
                            },
                        ]
                    },
                }
            if "iotgw_app_memory_bytes" in q:
                return {
                    "status": "success",
                    "data": {
                        "result": [
                            {
                                "metric": {"app": "agent"},
                                "value": [1, "64.0"],
                            },
                            {
                                "metric": {"app": "mqtt"},
                                "value": [1, "18.5"],
                            },
                        ]
                    },
                }
            if "iotgw_app_up" in q and "count(" not in q:
                return {
                    "status": "success",
                    "data": {
                        "result": [
                            {"metric": {"app": "agent"}, "value": [1, "1"]},
                            {"metric": {"app": "mqtt"}, "value": [1, "1"]},
                            {"metric": {"app": "decrypt"}, "value": [1, "1"]},
                            {"metric": {"app": "shipper"}, "value": [1, "0"]},
                            {"metric": {"app": "kafka"}, "value": [1, "1"]},
                        ]
                    },
                }
            if "iotgw_kafka_produce_total" in q:
                return {
                    "status": "success",
                    "data": {"result": [{"metric": {}, "value": [1, "4.5"]}]},
                }
            if "iotgw_kafka_up" in q:
                return {
                    "status": "success",
                    "data": {"result": [{"metric": {}, "value": [1, "1"]}]},
                }
            if "iotgw_decrypt_messages_total" in q:
                return {
                    "status": "success",
                    "data": {"result": [{"metric": {}, "value": [1, "12.5"]}]},
                }
            if "iotgw_loki_lines_sent_total" in q:
                return {
                    "status": "success",
                    "data": {"result": [{"metric": {}, "value": [1, "8.0"]}]},
                }
            val = "1"
            if "MemAvailable" in q and "MemTotal" in q and "100 *" in q:
                val = "50"
            elif "MemTotal" in q and "MemAvailable" in q:
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
            elif "iotgw_app_up" in q and "count(" in q:
                val = "3"
            elif "node_hwmon_temp" in q:
                val = "48.2"
            elif "node_boot_time" in q or "node_time_seconds" in q:
                val = "86400"
            elif "SwapTotal" in q:
                val = "12.5"
            elif "iowait" in q:
                val = "0.05"
            elif "node_procs_running" in q:
                val = "3"
            elif "node_procs_blocked" in q:
                val = "1"
            elif q.startswith("up") or 'up{' in q:
                val = "1"
            return {
                "status": "success",
                "data": {"result": [{"metric": {}, "value": [1, val]}]},
            }

        with patch("api.query._proxy_get", side_effect=fake_proxy):
            r = self.client.get(
                "/api/v1/query/summaries/raspi", params={"range": "15m"}
            )
        self.assertEqual(r.status_code, 200, r.text)
        body = r.json()
        self.assertTrue(body["up"])
        self.assertEqual(body["range"], "15m")
        self.assertEqual(body["metrics"]["cpu_cores"], 4)
        self.assertEqual(body["metrics"]["apps_up"], 4)
        self.assertEqual(body["metrics"]["apps_total"], 5)
        self.assertEqual(body["metrics"]["active_containers"], 4)
        self.assertEqual(body["metrics"]["mem_used_pct"], 50.0)
        self.assertEqual(body["metrics"]["temp_c"], 48.2)
        self.assertIn("cpu_pct", body["charts"])
        self.assertEqual(body["charts"]["cpu_pct"], [10.0, 20.0])
        self.assertEqual(body["cpu_sparkline_pct"], [10.0, 20.0])
        self.assertEqual(body["applications"]["status"][0]["name"], "Agent")
        self.assertTrue(body["applications"]["status"][0]["up"])
        status_by_id = {s["id"]: s for s in body["applications"]["status"]}
        self.assertIn("kafka", status_by_id)
        self.assertEqual(status_by_id["kafka"]["name"], "Kafka")
        self.assertTrue(status_by_id["kafka"]["up"])
        self.assertEqual(body["applications"]["activity"][0]["name"], "Decrypt msgs/min")
        activity_names = [a["name"] for a in body["applications"]["activity"]]
        self.assertIn("Kafka produce/min", activity_names)
        self.assertEqual(body["applications"]["cpu"][0]["name"], "agent")
        self.assertEqual(body["applications"]["mem_mib"][0]["name"], "agent")
        self.assertEqual(body["containers"]["cpu"][0]["name"], "agent")

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

        @contextmanager
        def open_ssh(_gw: dict[str, Any]) -> Iterator[_FakeSSH]:
            yield _FakeSSH()

        app = create_app(
            settings=settings, registry=self.registry, open_ssh=open_ssh
        )
        client = TestClient(app)
        r = client.get("/api/v1/query/summaries/sensors", params={"gateway_id": "gw1"})
        self.assertEqual(r.status_code, 401)
        with patch(
            "api.query._proxy_get",
            return_value={"status": "success", "data": {"result": []}},
        ):
            r2 = client.get(
                "/api/v1/query/summaries/sensors",
                params={"gateway_id": "gw1"},
                headers={"X-API-Token": "secret"},
            )
        self.assertEqual(r2.status_code, 200)


if __name__ == "__main__":
    unittest.main()
