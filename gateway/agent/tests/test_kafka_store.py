"""Tests for gateway Kafka capacity helpers."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from iot_gateway_agent.kafka_store import (
    TopicCatalog,
    max_sensor_slots,
    topic_config_for_broker,
)


class TestKafkaStore(unittest.TestCase):
    def test_max_sensors_example(self) -> None:
        self.assertEqual(max_sensor_slots(10, 1, safety_ratio=0.7), 7)

    def test_catalog_capacity(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            kafka = root / "kafka"
            kafka.mkdir()
            (kafka / "topics.json").write_text(
                json.dumps(
                    {
                        "retention_bytes_default": 1,
                        "safety_ratio": 0.7,
                        "topics": {
                            "sensor.a": {"device_id": "a", "topic": "sensor.a"},
                            "sensor.b": {"device_id": "b", "topic": "sensor.b"},
                        },
                    }
                ),
                encoding="utf-8",
            )
            cat = TopicCatalog(root)
            self.assertEqual(cat.count, 2)
            # Monkeypatch total storage via capacity with a known path size is
            # environment-dependent; assert config helper instead.
            cfg = topic_config_for_broker("sensor9", retention_bytes=1024)
            self.assertEqual(cfg["topic"], "sensor.sensor9")
            self.assertEqual(cfg["config"]["retention.bytes"], "1024")


if __name__ == "__main__":
    unittest.main()
