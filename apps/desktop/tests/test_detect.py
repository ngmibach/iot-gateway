"""Unit tests for environment detection helpers."""

from __future__ import annotations

import os
import unittest
from unittest import mock

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

    def test_native_windows_never_reports_in_wsl(self) -> None:
        """Packaged .exe / Windows Python must not treat \\\\wsl$ cwd as WSL."""
        if os.name != "nt":
            self.skipTest("Windows-only")
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("WSL_DISTRO_NAME", None)
            os.environ.pop("WSL_INTEROP", None)
            self.assertFalse(detect.in_wsl())
            self.assertEqual(detect.operator_runtime(), "windows")

    def test_in_wsl_false_on_nt_even_if_proc_readable(self) -> None:
        """Guard: /proc/version must not be consulted on native Windows."""
        with mock.patch.object(detect.os, "name", "nt"), mock.patch(
            "builtins.open", side_effect=AssertionError("must not open /proc on nt")
        ):
            self.assertFalse(detect.in_wsl())


if __name__ == "__main__":
    unittest.main()
