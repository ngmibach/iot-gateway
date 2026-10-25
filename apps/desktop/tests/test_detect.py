"""Unit tests for environment detection helpers."""

from __future__ import annotations

import unittest

from shell import detect


class DetectTests(unittest.TestCase):
    def test_snapshot_keys(self) -> None:
        snap = detect.environment_snapshot()
        self.assertIn("wsl", snap)
        self.assertIn("platform", snap)
        self.assertIn("runtime", snap)
        self.assertFalse(snap["docker_required"])
        self.assertFalse(snap["wsl_required"])
        self.assertNotIn("docker", snap)

    def test_operator_runtime_values(self) -> None:
        self.assertIn(detect.operator_runtime(), ("windows", "wsl", "linux"))


if __name__ == "__main__":
    unittest.main()
