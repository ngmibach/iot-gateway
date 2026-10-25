"""Decrypt worker device_id / delay helpers and Kafka handoff."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from iot_gateway_agent.decrypt_worker import (
    DecryptWorker,
    _delay_ms_from_payload,
    device_id_from_mqtt_topic,
)


class DeviceIdTests(unittest.TestCase):
    def test_sensors_prefix(self) -> None:
        self.assertEqual(device_id_from_mqtt_topic("sensors/sensor1/data"), "sensor1")

    def test_empty(self) -> None:
        self.assertEqual(device_id_from_mqtt_topic(""), "unknown")


class DelayTests(unittest.TestCase):
    def test_explicit_delay(self) -> None:
        self.assertEqual(
            _delay_ms_from_payload(json.dumps({"delay": 12.5}), received_ms=1000),
            12.5,
        )

    def test_ts_ms(self) -> None:
        self.assertEqual(
            _delay_ms_from_payload(json.dumps({"ts_ms": 900}), received_ms=1000),
            100.0,
        )


class DecryptWorkerKafkaTests(unittest.TestCase):
    def test_produce_after_plain_payload(self) -> None:
        kafka = mock.Mock()
        with tempfile.TemporaryDirectory() as tmp:
            log_path = Path(tmp) / "sensor_data.log"
            worker = DecryptWorker(log_path=log_path, kafka=kafka)
            payload = json.dumps({"temp": 1, "delay": 3}).encode("utf-8")
            with mock.patch(
                "iot_gateway_agent.decrypt_worker.decrypt_wrapper_payload",
                return_value=json.dumps({"temp": 1, "delay": 3}),
            ):
                worker._handle_message("sensors/sensor9/x", payload)
            kafka.produce.assert_called_once()
            args = kafka.produce.call_args[0]
            self.assertEqual(args[0], "sensor.sensor9")
            snap = worker.device_snapshot()
            self.assertEqual(snap["sensor9"].messages_ok, 1)
            self.assertEqual(snap["sensor9"].last_delay_ms, 3.0)


if __name__ == "__main__":
    unittest.main()
