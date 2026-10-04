"""Minimal tests for health/info JSON shape."""

from __future__ import annotations

import unittest
from unittest import mock

from iot_gateway_agent import AGENT_PORT, HEALTH_PATH, MQTT_TLS_PORT, __version__
from iot_gateway_agent.health import build_health, build_info


class HealthShapeTests(unittest.TestCase):
    def test_health_without_docker(self) -> None:
        with mock.patch("iot_gateway_agent.health.shutil.which", return_value=None):
            payload = build_health(mdns_enabled=False)

        self.assertEqual(payload["status"], "ok")
        self.assertEqual(payload["agent"], "iot-gateway-agent")
        self.assertEqual(payload["version"], __version__)
        self.assertIn("hostname", payload)
        self.assertIs(payload["mdns"], False)
        self.assertEqual(payload["port"], AGENT_PORT)
        self.assertNotIn("services", payload)

    def test_health_degraded_when_expected_missing(self) -> None:
        fake_services = [{"name": "other", "state": "running", "health": ""}]
        with mock.patch(
            "iot_gateway_agent.health._docker_compose_ps",
            return_value=fake_services,
        ):
            payload = build_health(mdns_enabled=True)

        self.assertEqual(payload["status"], "degraded")
        self.assertIs(payload["mdns"], True)
        self.assertEqual(payload["services"], fake_services)

    def test_health_ok_when_expected_running(self) -> None:
        fake_services = [
            {"name": "iot-mosquitto", "state": "running", "health": ""},
            {"name": "iot-haproxy", "state": "running", "health": ""},
            {"name": "iot-nodered", "state": "running", "health": ""},
            {"name": "iot-ids", "state": "running", "health": ""},
        ]
        with mock.patch(
            "iot_gateway_agent.health._docker_compose_ps",
            return_value=fake_services,
        ):
            payload = build_health(mdns_enabled=True)

        self.assertEqual(payload["status"], "ok")

    def test_info_shape(self) -> None:
        payload = build_info()
        self.assertEqual(payload["service"], "iot-gateway-agent")
        self.assertEqual(payload["version"], __version__)
        self.assertEqual(payload["port"], AGENT_PORT)
        self.assertEqual(payload["mqtts"], MQTT_TLS_PORT)
        self.assertEqual(payload["path"], HEALTH_PATH)
        self.assertTrue(payload["read_only"])
        self.assertIn("GET /v1/health", payload["api"])
        self.assertIn("GET /v1/info", payload["api"])


if __name__ == "__main__":
    unittest.main()
