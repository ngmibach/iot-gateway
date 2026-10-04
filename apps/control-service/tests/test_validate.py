"""Topic / user / IP validation tests."""

from __future__ import annotations

import unittest

from actions.validate import validate_ip_or_cidr, validate_topic, validate_user_id


class TestValidate(unittest.TestCase):
    def test_topics_legal(self) -> None:
        for t in ("sensors/sensor1/#", "alerts/+", "#", "+", "$SYS/#", "a/b/c"):
            self.assertEqual(validate_topic(t), t)

    def test_topics_illegal(self) -> None:
        for t in ("foo/#/bar", "a+", "sen#sor", ""):
            with self.assertRaises(ValueError):
                validate_topic(t)

    def test_reserved_user(self) -> None:
        with self.assertRaises(ValueError):
            validate_user_id("nodered")
        with self.assertRaises(ValueError):
            validate_user_id("anonymous")

    def test_ip(self) -> None:
        self.assertEqual(validate_ip_or_cidr("10.0.0.1"), "10.0.0.1")
        self.assertEqual(validate_ip_or_cidr("172.22.0.0/16"), "172.22.0.0/16")
        with self.assertRaises(ValueError):
            validate_ip_or_cidr("not-an-ip")


if __name__ == "__main__":
    unittest.main()
