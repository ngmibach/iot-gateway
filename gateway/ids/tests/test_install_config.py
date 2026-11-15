from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import yaml

from ids_gateway.install_config import prepare_config


class InstallConfigTests(unittest.TestCase):
    def test_pins_model_and_event_paths_but_preserves_operator_settings(self) -> None:
        defaults = Path(__file__).parents[1] / "configs" / "ids_config.yaml"
        with tempfile.TemporaryDirectory() as temp_dir:
            target = Path(temp_dir) / "ids_config.yaml"
            target.write_text(
                "gateway:\n  enabled: true\n  suspicious_threshold: 0.3\n"
                "  behavioral_rules:\n    max_message_rate_per_sec: 2.5\n",
                encoding="utf-8",
            )
            config = prepare_config(target, defaults)
            self.assertTrue(config["gateway"]["enabled"])
            self.assertEqual(config["gateway"]["suspicious_threshold"], 0.3)
            self.assertEqual(
                config["gateway"]["behavioral_rules"]["max_message_rate_per_sec"],
                2.5,
            )
            self.assertEqual(
                config["gateway"]["sensor_log"]["path"],
                "/var/lib/iot-gateway-agent/logs/ids_events.jsonl",
            )
            self.assertEqual(
                config["model"]["path"],
                "models/ids_model.joblib",
            )
            self.assertNotIn(b"\r\n", target.read_bytes())
            self.assertEqual(yaml.safe_load(target.read_text(encoding="utf-8")), config)


if __name__ == "__main__":
    unittest.main()
