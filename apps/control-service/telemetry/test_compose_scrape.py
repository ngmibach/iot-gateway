"""Unit tests for compose generation and prometheus scrape rendering."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from telemetry.compose import ComposeProfile, generate_compose_yaml, write_stack_files
from telemetry.images import required_images
from telemetry.scrape import render_prometheus_scrape


class ComposeScrapeTests(unittest.TestCase):
    def test_linux_host_publishes_loki_uses_prom_host(self) -> None:
        yml = generate_compose_yaml(ComposeProfile.LINUX_HOST)
        self.assertIn("iotgw-loki", yml)
        self.assertIn("3100:3100", yml)
        self.assertIn("network_mode: host", yml)
        self.assertIn("grafana/loki:latest", yml)
        self.assertIn("prom/prometheus:latest", yml)
        self.assertIn("iotgw_loki_data", yml)
        self.assertIn("iotgw_prom_data", yml)
        self.assertIn("do not edit by hand", yml.lower())

    def test_wsl2_binds_loki_all_interfaces_prom_localhost(self) -> None:
        yml = generate_compose_yaml(ComposeProfile.WSL2)
        self.assertIn("0.0.0.0:3100:3100", yml)
        self.assertIn("127.0.0.1:9090:9090", yml)
        self.assertNotIn("network_mode: host", yml)

    def test_windows_docker_desktop_bridge_both(self) -> None:
        yml = generate_compose_yaml(ComposeProfile.WINDOWS_DOCKER_DESKTOP)
        self.assertIn("3100:3100", yml)
        self.assertIn("9090:9090", yml)

    def test_render_scrape_targets(self) -> None:
        text = render_prometheus_scrape("192.168.1.50", cadvisor_port=8080)
        self.assertIn("192.168.1.50:9100", text)
        self.assertIn("192.168.1.50:8080", text)
        self.assertNotIn("{{GATEWAY_IP}}", text)
        self.assertIn("cadvisor", text)
        self.assertIn("mqtt_connected_sensor", text)

    def test_write_stack_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = write_stack_files(
                root,
                profile=ComposeProfile.LINUX_BRIDGE,
                prometheus_yml=render_prometheus_scrape("10.0.0.8"),
            )
            self.assertTrue(path.is_file())
            self.assertTrue((root / "config" / "loki-config.yaml").is_file())
            self.assertTrue((root / "config" / "prometheus.yml").is_file())
            body = path.read_text(encoding="utf-8")
            self.assertIn("9090:9090", body)

    def test_image_set_lists_loki_prometheus(self) -> None:
        imgs = required_images()
        self.assertIn("grafana/loki:latest", imgs)
        self.assertIn("prom/prometheus:latest", imgs)


if __name__ == "__main__":
    unittest.main()
