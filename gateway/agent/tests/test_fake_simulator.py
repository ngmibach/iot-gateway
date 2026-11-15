"""Unit tests for fake-sensor Simulate attack helpers."""

from __future__ import annotations

import unittest
import tempfile

from iot_gateway_agent.envelope_v1 import DeviceSecrets
from iot_gateway_agent.fake_sensor.simulator import (
    _build_envelope_pubs,
    _resolve_topic,
    _rewrite_topic_for_wrong_topic,
)


class IDSTestOrderTests(unittest.TestCase):
    def test_reverse_order_preserves_both_valid_envelope_parts(self) -> None:
        secrets = DeviceSecrets(
            device_id="sensor1",
            profile="v1-psk",
            mac_key=b"a" * 32,
            wrap_secret=b"b" * 32,
        )
        with tempfile.TemporaryDirectory() as data_dir:
            normal = _build_envelope_pubs(
                {"device_id": "sensor1"}, {}, secrets=secrets, data_dir=data_dir
            )
            reverse = _build_envelope_pubs(
                {"device_id": "sensor1"}, {}, secrets=secrets,
                data_dir=data_dir, reverse_order=True,
            )
        self.assertEqual([topic for topic, _ in normal], [
            "sensors/sensor1/env/key", "sensors/sensor1/env/data"
        ])
        self.assertEqual([topic for topic, _ in reverse], [
            "sensors/sensor1/env/data", "sensors/sensor1/env/key"
        ])


class WrongTopicTests(unittest.TestCase):
    def test_resolve_topic_when_attack_off(self) -> None:
        cfg = {
            "device_id": "fake2",
            "topic": "sensors/fake2/process",
            "behaviors": {"wrong_topic": False},
        }
        self.assertEqual(_resolve_topic(cfg), "sensors/fake2/process")

    def test_resolve_topic_when_attack_on(self) -> None:
        cfg = {
            "device_id": "fake2",
            "topic": "sensors/fake2/process",
            "behaviors": {"wrong_topic": True},
        }
        self.assertEqual(_resolve_topic(cfg), "sensors/__denied__/fake2/process")

    def test_rewrite_envelope_topics(self) -> None:
        behaviors = {"wrong_topic": True}
        self.assertEqual(
            _rewrite_topic_for_wrong_topic(
                "sensors/fake2/env/key", "fake2", behaviors
            ),
            "sensors/__denied__/fake2/env/key",
        )
        self.assertEqual(
            _rewrite_topic_for_wrong_topic(
                "sensors/fake2/env/data", "fake2", behaviors
            ),
            "sensors/__denied__/fake2/env/data",
        )
        self.assertEqual(
            _rewrite_topic_for_wrong_topic(
                "sensors/fake2/process", "fake2", behaviors
            ),
            "sensors/__denied__/fake2/process",
        )

    def test_rewrite_noop_when_off(self) -> None:
        behaviors = {"wrong_topic": False}
        self.assertEqual(
            _rewrite_topic_for_wrong_topic(
                "sensors/fake2/env/key", "fake2", behaviors
            ),
            "sensors/fake2/env/key",
        )


if __name__ == "__main__":
    unittest.main()
