"""Unit tests for Loki/Prometheus/Grafana readiness helpers."""

from __future__ import annotations

import unittest
from unittest import mock

from telemetry.readiness import (
    ProbeResult,
    check_grafana,
    check_loki,
    check_prometheus,
    gateway_loki_ready_curl,
    probe_http,
    wait_ready,
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

    def test_check_grafana_uses_unverified_context(self) -> None:
        with mock.patch(
            "telemetry.readiness.ssl._create_unverified_context"
        ) as mk_ctx:
            mk_ctx.return_value = object()
            with mock.patch(
                "telemetry.readiness.urllib.request.urlopen",
                return_value=_FakeResp(200, b'{"database":"ok"}'),
            ) as urlopen:
                r = check_grafana("https://127.0.0.1:9140/", timeout=1.5)
        self.assertTrue(r.ok)
        mk_ctx.assert_called_once_with()
        self.assertEqual(
            urlopen.call_args.kwargs.get("context"), mk_ctx.return_value
        )
        self.assertIn("/api/health", r.url)

    def test_wait_ready_optional_grafana(self) -> None:
        ok = ProbeResult(True, "u", "ok")
        with mock.patch(
            "telemetry.readiness.check_loki", return_value=ok
        ):
            with mock.patch(
                "telemetry.readiness.check_prometheus", return_value=ok
            ):
                with mock.patch(
                    "telemetry.readiness.check_grafana", return_value=ok
                ) as cg:
                    without = wait_ready(timeout_s=0.1, interval_s=0.01)
                    with_g = wait_ready(
                        grafana_url="https://127.0.0.1:9140",
                        timeout_s=0.1,
                        interval_s=0.01,
                    )
        self.assertNotIn("grafana", without)
        self.assertIn("grafana", with_g)
        cg.assert_called()

    def test_gateway_loki_ready_curl(self) -> None:
        self.assertEqual(
            gateway_loki_ready_curl("10.0.0.5", port=3100, max_time=5),
            "curl -fsS --max-time 5 http://10.0.0.5:3100/ready",
        )
        with self.assertRaises(ValueError):
            gateway_loki_ready_curl("  ")


if __name__ == "__main__":
    unittest.main()
