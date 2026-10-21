"""Local registry upsert used after Install gateway."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from shell import registry_gateways


class RegistryGatewaysTests(unittest.TestCase):
    def test_fingerprint_from_settings(self) -> None:
        settings = {
            "ssh_host_pins": {
                "172.20.10.2:22": {"fingerprint_sha256": "SHA256:abc"},
            }
        }
        self.assertEqual(
            registry_gateways.fingerprint_from_settings(settings, "172.20.10.2", 22),
            "SHA256:abc",
        )
        self.assertEqual(
            registry_gateways.fingerprint_from_settings(settings, "10.0.0.1", 22),
            "",
        )

    def test_upsert_local_gateway_writes_row(self) -> None:
        from registry.registry import Registry

        with tempfile.TemporaryDirectory() as tmp:
            data = Path(tmp)
            with mock.patch.object(registry_gateways, "ensure_data_dir", return_value=data):
                row = registry_gateways.upsert_local_gateway(
                    gateway_id="gateway",
                    host="172.20.10.2",
                    ssh_user="admin",
                    fingerprint="SHA256:test",
                    monitoring_ip="172.20.10.3",
                )
            self.assertEqual(row["id"], "gateway")
            self.assertEqual(row["host"], "172.20.10.2")
            self.assertEqual(row["ssh_user"], "admin")
            self.assertEqual(row["install_root"], "/opt/iot-gateway-agent")
            self.assertEqual(row["agent_url"], "http://172.20.10.2:9139")

            reg = Registry(str(data / "registry.sqlite"))
            try:
                listed = reg.list_gateways()
            finally:
                reg.close()
            self.assertEqual(len(listed), 1)
            self.assertEqual(listed[0]["id"], "gateway")


if __name__ == "__main__":
    unittest.main()
