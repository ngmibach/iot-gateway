from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from ids_gateway.install_config import prepare_config
from ids_gateway.log_capture import SensorLogCapture


def _event(device_id: str = "sensor1") -> bytes:
    event = {
        "event_type": "sensor_data",
        "deviceId": device_id,
        "topic": f"sensors/{device_id}/process",
        "payload": {"temperature": 21},
        "gateway_received_at": "2026-11-01T10:00:00+00:00",
        "delay": 0.125,
        "broker_port": 8883,
        "payload_size_bytes": 20,
    }
    return (json.dumps(event, separators=(",", ":")) + "\n").encode()


class StructuredInputTests(unittest.TestCase):
    def test_partial_jsonl_is_buffered_then_processed_once_without_source_ip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "ids_events.jsonl"
            path.touch()
            capture = SensorLogCapture(str(path))
            self.assertEqual(capture.poll_once(), {})

            line = _event()
            with path.open("ab") as fh:
                fh.write(line[:17])
            self.assertEqual(capture.poll_once(), {})
            with path.open("ab") as fh:
                fh.write(line[17:])

            batches = capture.poll_once()
            record = batches["sensor1"][0]
            self.assertEqual(record.mqtt_device_id, "sensor1")
            self.assertEqual(record.mqtt_topic, "sensors/sensor1/process")
            self.assertEqual(record.mqtt_payload, {"temperature": 21})
            self.assertEqual(record.mqtt_delay, 0.125)
            self.assertEqual(record.dst_port, 8883)
            self.assertEqual(record.src_ip, "")
            self.assertEqual(record.observed_src_ip, "")
            self.assertEqual(capture.poll_once(), {})

    def test_file_replacement_and_truncation_are_followed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "ids_events.jsonl"
            path.touch()
            capture = SensorLogCapture(str(path))
            capture.poll_once()

            path.write_bytes(_event("sensor1"))
            self.assertEqual(len(capture.poll_once()["sensor1"]), 1)

            path.write_bytes(_event("sensor2"))
            rewritten = capture.poll_once()
            self.assertEqual(len(rewritten["sensor2"]), 1)

            rotated = path.with_suffix(".jsonl.1")
            os.replace(path, rotated)
            path.write_bytes(_event("sensor3"))
            self.assertEqual(len(capture.poll_once()["sensor3"]), 1)

            path.write_bytes(b"")
            self.assertEqual(capture.poll_once(), {})
            with path.open("ab") as fh:
                fh.write(_event("sensor4"))
            self.assertEqual(len(capture.poll_once()["sensor4"]), 1)

    def test_config_migration_preserves_settings_and_uses_bundled_model(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "ids_config.yaml"
            path.write_text(
                "enabled: false\ngateway:\n  suspicious_threshold: 0.42\n"
                "  behavioral_rules:\n    max_message_rate_per_sec: 2.5\n"
                "model:\n  path: user-uploaded.joblib\n",
                encoding="utf-8",
            )
            config = prepare_config(
                path,
                event_log="/var/lib/iot-gateway-agent/logs/ids_events.jsonl",
                alert_log="/var/lib/iot-gateway-agent/logs/ids_alerts.log",
                mosquitto_log="/var/log/mosquitto/mosquitto.log",
            )
            saved = path.read_text(encoding="utf-8")
            self.assertFalse(config["enabled"])
            self.assertEqual(config["gateway"]["suspicious_threshold"], 0.42)
            self.assertEqual(
                config["gateway"]["behavioral_rules"]["max_message_rate_per_sec"],
                2.5,
            )
            self.assertFalse(config["gateway"]["behavioral_rules"]["enforce_allowed_ips"])
            self.assertEqual(
                config["gateway"]["sensor_log"]["path"],
                "/var/lib/iot-gateway-agent/logs/ids_events.jsonl",
            )
            self.assertEqual(config["model"]["path"], "models/ids_model.joblib")
            self.assertNotIn("user-uploaded.joblib", saved)


if __name__ == "__main__":
    unittest.main()
