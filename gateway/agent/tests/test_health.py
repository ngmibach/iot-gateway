"""Minimal tests for health/info JSON shape, mutations, and mDNS fallback."""

from __future__ import annotations

import json
import unittest
from http.server import BaseHTTPRequestHandler
from io import BytesIO
from unittest import mock

from iot_gateway_agent import AGENT_PORT, HEALTH_PATH, MQTT_TLS_PORT, __version__
from iot_gateway_agent.health import build_health, build_info
from iot_gateway_agent.mdns import start_mdns
from iot_gateway_agent.server import make_handler


class HealthShapeTests(unittest.TestCase):
    def test_health_liveness(self) -> None:
        payload = build_health(mdns_enabled=False, port=19138)
        self.assertEqual(payload["status"], "ok")
        self.assertEqual(payload["agent"], "iot-gateway-agent")
        self.assertEqual(payload["version"], __version__)
        self.assertIn("hostname", payload)
        self.assertIs(payload["mdns"], False)
        self.assertEqual(payload["port"], 19138)
        self.assertNotIn("services", payload)

    def test_health_default_port(self) -> None:
        payload = build_health(mdns_enabled=True)
        self.assertEqual(payload["port"], AGENT_PORT)
        self.assertIs(payload["mdns"], True)

    def test_info_shape(self) -> None:
        payload = build_info(port=19138)
        self.assertEqual(payload["service"], "iot-gateway-agent")
        self.assertEqual(payload["version"], __version__)
        self.assertEqual(payload["port"], 19138)
        self.assertEqual(payload["mqtts"], MQTT_TLS_PORT)
        self.assertEqual(payload["path"], HEALTH_PATH)
        self.assertIn("GET /v1/health", payload["api"])
        self.assertIn("GET /v1/info", payload["api"])


class MdnsTests(unittest.TestCase):
    def test_start_mdns_without_zeroconf(self) -> None:
        import builtins

        real_import = builtins.__import__

        def _fake_import(name, *args, **kwargs):
            if name == "zeroconf" or name.startswith("zeroconf."):
                raise ImportError("no zeroconf")
            return real_import(name, *args, **kwargs)

        with mock.patch("builtins.__import__", side_effect=_fake_import):
            handle, enabled = start_mdns(9139)

        self.assertIsNone(handle)
        self.assertIs(enabled, False)


class HandlerTests(unittest.TestCase):
    def _dispatch(self, path: str, method: str = "GET"):
        def health_fn():
            return {"status": "ok", "agent": "iot-gateway-agent", "port": 9138}

        def info_fn():
            return {"service": "iot-gateway-agent", "port": 9138}

        handler_cls = make_handler(health_fn, info_fn)
        responses: dict = {"headers": []}

        class Capture(handler_cls):  # type: ignore[valid-type,misc]
            def send_response(self, code, message=None):
                responses["code"] = code

            def send_header(self, keyword, value):
                responses["headers"].append((keyword, value))

            def end_headers(self):
                pass

            def log_message(self, fmt, *args):
                pass

        h = Capture.__new__(Capture)
        BaseHTTPRequestHandler.__init__.__doc__  # keep type checkers quiet
        h.client_address = ("127.0.0.1", 1)
        h.request_version = "HTTP/1.1"
        h.command = method
        h.path = path
        h.headers = {}
        h.wfile = BytesIO()
        h.rfile = BytesIO()
        getattr(h, f"do_{method}")()
        body = h.wfile.getvalue()
        payload = json.loads(body.decode("utf-8")) if body else None
        return responses.get("code"), payload, responses["headers"]

    def test_get_health(self) -> None:
        code, body, _ = self._dispatch("/v1/health")
        self.assertEqual(code, 200)
        self.assertEqual(body["status"], "ok")

    def test_get_info(self) -> None:
        code, body, _ = self._dispatch("/v1/info")
        self.assertEqual(code, 200)
        self.assertEqual(body["service"], "iot-gateway-agent")

    def test_root_not_aliased(self) -> None:
        code, body, _ = self._dispatch("/")
        self.assertEqual(code, 404)
        self.assertEqual(body["error"], "not found")

    def test_mutations_rejected(self) -> None:
        for method in ("POST", "PUT", "DELETE", "PATCH"):
            code, body, headers = self._dispatch("/v1/health", method=method)
            self.assertEqual(code, 405, method)
            self.assertIn("read-only", body["error"])
            allow = dict(headers).get("Allow", "")
            self.assertIn("GET", allow, method)


if __name__ == "__main__":
    unittest.main()
