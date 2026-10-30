"""Prometheus scrape template must stay valid for Prometheus to start."""

from __future__ import annotations

import re
import unittest
from pathlib import Path

from telemetry.scrape import _DEFAULT_TEMPLATE, render_prometheus_scrape


def _parse_duration_seconds(text: str) -> float:
    m = re.fullmatch(r"(\d+(?:\.\d+)?)(ms|s|m)", text.strip())
    if not m:
        raise ValueError(f"unsupported duration: {text!r}")
    value = float(m.group(1))
    unit = m.group(2)
    if unit == "ms":
        return value / 1000.0
    if unit == "m":
        return value * 60.0
    return value


class TestPrometheusScrape(unittest.TestCase):
    def test_default_template_timeout_not_greater_than_interval(self) -> None:
        interval = re.search(r"scrape_interval:\s*(\S+)", _DEFAULT_TEMPLATE)
        timeout = re.search(r"scrape_timeout:\s*(\S+)", _DEFAULT_TEMPLATE)
        self.assertIsNotNone(interval)
        self.assertIsNotNone(timeout)
        # Job-level values are the second scrape_interval match.
        intervals = re.findall(r"scrape_interval:\s*(\S+)", _DEFAULT_TEMPLATE)
        self.assertGreaterEqual(len(intervals), 2)
        job_interval = _parse_duration_seconds(intervals[1])
        job_timeout = _parse_duration_seconds(timeout.group(1))
        self.assertLessEqual(
            job_timeout,
            job_interval,
            "Prometheus refuses to start when scrape_timeout > scrape_interval",
        )

    def test_render_includes_gateway_target(self) -> None:
        yml = render_prometheus_scrape("172.20.10.2", template=_DEFAULT_TEMPLATE)
        self.assertIn("172.20.10.2:9139", yml)
        self.assertIn("iot-gateway-agent", yml)

    def test_repo_template_timeout_not_greater_than_interval(self) -> None:
        repo = (
            Path(__file__).resolve().parents[3]
            / "deploy"
            / "templates"
            / "prometheus.yml"
        )
        if not repo.is_file():
            self.skipTest("repo template missing")
        text = repo.read_text(encoding="utf-8")
        intervals = re.findall(r"scrape_interval:\s*(\S+)", text)
        timeouts = re.findall(r"scrape_timeout:\s*(\S+)", text)
        self.assertGreaterEqual(len(intervals), 2)
        self.assertTrue(timeouts, "repo template should set scrape_timeout explicitly")
        self.assertLessEqual(
            _parse_duration_seconds(timeouts[0]),
            _parse_duration_seconds(intervals[1]),
        )


if __name__ == "__main__":
    unittest.main()
