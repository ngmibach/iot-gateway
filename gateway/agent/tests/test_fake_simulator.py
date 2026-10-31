"""Unit tests for fake-sensor Simulate attack helpers."""

from __future__ import annotations

import unittest

from iot_gateway_agent.fake_sensor.simulator import (
    _resolve_topic,
    _rewrite_topic_for_wrong_topic,
)


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
