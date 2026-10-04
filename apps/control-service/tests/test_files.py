"""Tests for ACL / password / allow-list pure helpers."""

from __future__ import annotations

import unittest

from actions import files as fileops


SAMPLE_ACL = """user nodered
topic readwrite #
topic read $SYS/#

user sensor1
topic readwrite sensors/sensor1/#
topic read alerts/+

user anonymous
topic none
"""


class TestAclHelpers(unittest.TestCase):
    def test_append_user(self) -> None:
        out = fileops.append_user_acl(
            SAMPLE_ACL, "sensor9", topic_rw="sensors/sensor9/#", topic_r="alerts/+"
        )
        self.assertIn("user sensor9\n", out)
        self.assertIn("topic readwrite sensors/sensor9/#\n", out)
        self.assertIn("topic read alerts/+\n", out)

    def test_upsert_replaces_existing(self) -> None:
        once = fileops.upsert_user_acl(
            SAMPLE_ACL, "sensor1", topic_rw="sensors/sensor1/new/#"
        )
        twice = fileops.upsert_user_acl(
            once, "sensor1", topic_rw="sensors/sensor1/final/#", topic_r="alerts/+"
        )
        self.assertEqual(twice.count("user sensor1\n"), 1)
        self.assertIn("topic readwrite sensors/sensor1/final/#\n", twice)
        self.assertNotIn("topic readwrite sensors/sensor1/#\n", twice)
        self.assertIn("topic read alerts/+\n", twice)

    def test_upsert_appends_new(self) -> None:
        out = fileops.upsert_user_acl(
            SAMPLE_ACL, "sensor9", topic_rw="sensors/sensor9/#"
        )
        self.assertEqual(out.count("user sensor9\n"), 1)

    def test_update_add_and_delete(self) -> None:
        out = fileops.update_user_acl(
            SAMPLE_ACL,
            "sensor1",
            add_rw=["sensors/sensor1/extra"],
            delete_r=["alerts/+"],
        )
        self.assertIn("topic readwrite sensors/sensor1/extra\n", out)
        self.assertNotIn("topic read alerts/+\n", out)
        self.assertIn("user nodered\n", out)
        self.assertIn("user anonymous\n", out)

    def test_update_missing_user(self) -> None:
        with self.assertRaises(ValueError):
            fileops.update_user_acl(SAMPLE_ACL, "nope", add_rw=["x"])

    def test_remove_user(self) -> None:
        out = fileops.remove_user_acl(SAMPLE_ACL, "sensor1")
        self.assertNotIn("user sensor1\n", out)
        self.assertIn("user nodered\n", out)

    def test_merge_password_replace_and_append(self) -> None:
        content = "sensor1:$7$1000$aaa$bbb\nnodered:$7$1000$ccc$ddd\n"
        merged = fileops.merge_password_line(content, "sensor1:$7$1000$NEW$HASH")
        self.assertIn("sensor1:$7$1000$NEW$HASH\n", merged)
        self.assertIn("nodered:$7$1000$ccc$ddd\n", merged)
        appended = fileops.merge_password_line(content, "sensor9:$7$1000$x$y")
        self.assertTrue(appended.strip().endswith("sensor9:$7$1000$x$y"))

    def test_remove_password(self) -> None:
        content = "sensor1:$7$1000$a$b\nsensor2:$7$1000$c$d\n"
        out = fileops.remove_password_user(content, "sensor1")
        self.assertNotIn("sensor1:", out)
        self.assertIn("sensor2:", out)

    def test_allowlist_add_dedupe_sort(self) -> None:
        content = "10.0.0.2\n10.0.0.1\n"
        out = fileops.add_allowlist_ips(content, ["10.0.0.1", "10.0.0.3"])
        self.assertEqual(out, "10.0.0.1\n10.0.0.2\n10.0.0.3\n")

    def test_allowlist_remove_and_clear(self) -> None:
        content = "10.0.0.1\n10.0.0.2\n"
        out = fileops.remove_allowlist_ips(content, ["10.0.0.1"])
        self.assertEqual(out, "10.0.0.2\n")
        self.assertEqual(fileops.clear_allowlist(content), "")


if __name__ == "__main__":
    unittest.main()
