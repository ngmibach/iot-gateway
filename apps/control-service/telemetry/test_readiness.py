"""Unit tests for Loki/Prometheus readiness helpers."""

from __future__ import annotations

import unittest
from unittest import mock

from telemetry.readiness import (
    check_loki,
    check_prometheus,
    gateway_loki_ready_curl,
    probe_http,
)


class _FakeResp:
    def __init__(self, code: int, body: bytes = b"ready"):
        self.status = code
        self._body = body

    def read(self, _n: int = -1) -> bytes:
        return self._body

    def getcode(self) -> int:
        return self.status

    def __enter__(self) -> "_FakeResp":
        return self

    def __exit__(self, *exc: object) -> None:
        return None


class ReadinessTests(unittest.TestCase):
    def test_probe_http_ok(self) -> None:
        with mock.patch(
            "telemetry.readiness.urllib.request.urlopen",
            return_value=_FakeResp(200, b"ok"),
        ):
            r = probe_http("http://example/ready")
        self.assertTrue(r.ok)
        self.assertIn("200", r.detail)

    def test_probe_http_fail(self) -> None:
        with mock.patch(
            "telemetry.readiness.urllib.request.urlopen",
            side_effect=OSError("refused"),
        ):
            r = probe_http("http://example/ready")
        self.assertFalse(r.ok)
        self.assertIn("OSError", r.detail)

    def test_check_loki_path(self) -> None:
        with mock.patch(
            "telemetry.readiness.probe_http",
            return_value=mock.Mock(ok=True, url="u", detail="d"),
        ) as ph:
            check_loki("http://127.0.0.1:3100/")
            ph.assert_called_once_with("http://127.0.0.1:3100/ready", timeout=5.0)

    def test_check_prometheus_falls_back(self) -> None:
        calls: list[str] = []

        def fake(url: str, *, timeout: float = 5.0):
            calls.append(url)
            from telemetry.readiness import ProbeResult

            if "/-/healthy" in url:
                return ProbeResult(False, url, "boom")
            return ProbeResult(True, url, "ok")

        with mock.patch("telemetry.readiness.probe_http", side_effect=fake):
            r = check_prometheus("http://127.0.0.1:9090")
        self.assertTrue(r.ok)
        self.assertEqual(
            calls,
            [
                "http://127.0.0.1:9090/-/healthy",
                "http://127.0.0.1:9090/api/v1/status/config",
            ],
        )

    def test_gateway_loki_ready_curl(self) -> None:
        self.assertEqual(
            gateway_loki_ready_curl("10.0.0.5", port=3100, max_time=5),
            "curl -fsS --max-time 5 http://10.0.0.5:3100/ready",
        )
        with self.assertRaises(ValueError):
            gateway_loki_ready_curl("  ")


if __name__ == "__main__":
    unittest.main()
