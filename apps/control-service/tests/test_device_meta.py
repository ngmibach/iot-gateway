"""Unit tests for devices.meta_json helpers (is_fake / kafka merge)."""

from __future__ import annotations

import unittest

from api.device_meta import (
    fake_block,
    is_fake_meta,
    merge_device_meta,
    parse_meta,
)


class DeviceMetaTests(unittest.TestCase):
    def test_parse_meta_dict_and_json(self) -> None:
        self.assertEqual(parse_meta(None), {})
        self.assertEqual(parse_meta({"a": 1}), {"a": 1})
        self.assertEqual(parse_meta('{"kafka_topic":"sensor.x"}'), {"kafka_topic": "sensor.x"})
        self.assertEqual(parse_meta("not-json"), {})

    def test_is_fake_meta(self) -> None:
        self.assertFalse(is_fake_meta(None))
        self.assertFalse(is_fake_meta({}))
        self.assertFalse(is_fake_meta({"is_fake": False}))
        self.assertFalse(is_fake_meta({"is_fake": "yes"}))
        self.assertTrue(is_fake_meta({"is_fake": True}))

    def test_merge_kafka_preserves_other_keys(self) -> None:
        meta = merge_device_meta(
            {"extra": 1, "is_fake": True, "fake": {"status": "running"}},
            kafka_topic="sensor.a",
            kafka_retention_bytes=100,
        )
        self.assertEqual(meta["extra"], 1)
        self.assertEqual(meta["kafka_topic"], "sensor.a")
        self.assertEqual(meta["kafka_retention_bytes"], 100)
        self.assertTrue(meta["is_fake"])
        self.assertEqual(fake_block(meta), {"status": "running"})

    def test_clear_fake_on_real_register(self) -> None:
        meta = merge_device_meta(
            {
                "kafka_topic": "sensor.old",
                "is_fake": True,
                "fake": {"ip": "10.255.0.2", "status": "running"},
            },
            kafka_topic="sensor.new",
            kafka_retention_bytes=50,
            clear_fake=True,
        )
        self.assertEqual(meta["kafka_topic"], "sensor.new")
        self.assertEqual(meta["kafka_retention_bytes"], 50)
        self.assertNotIn("is_fake", meta)
        self.assertNotIn("fake", meta)

    def test_merge_fake_block(self) -> None:
        meta = merge_device_meta(
            {"kafka_topic": "sensor.f1"},
            is_fake=True,
            fake={"ip": "10.255.0.2", "status": "running"},
        )
        self.assertTrue(meta["is_fake"])
        self.assertEqual(meta["fake"]["ip"], "10.255.0.2")
        meta2 = merge_device_meta(
            meta,
            fake={"status": "stopped", "send_interval_ms": 500},
        )
        self.assertEqual(meta2["fake"]["ip"], "10.255.0.2")
        self.assertEqual(meta2["fake"]["status"], "stopped")
        self.assertEqual(meta2["fake"]["send_interval_ms"], 500)


if __name__ == "__main__":
    unittest.main()
