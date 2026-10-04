"""Unit tests for Docker/WSL detection helpers."""

from __future__ import annotations

import unittest
from unittest import mock

from shell import detect


class DetectDockerTests(unittest.TestCase):
    def test_missing_docker(self) -> None:
        with mock.patch("shell.detect.shutil.which", return_value=None):
            st = detect.detect_docker()
        self.assertFalse(st.present)
        self.assertFalse(st.healthy)
        self.assertIn("Docker", st.hint)

    def test_healthy_docker(self) -> None:
        ver = mock.Mock(returncode=0, stdout="27.0.0\n", stderr="")
        info = mock.Mock(returncode=0, stdout="Server:\n", stderr="")

        def run(args, **kwargs):
            if args[1] == "version":
                return ver
            return info

        with (
            mock.patch("shell.detect.shutil.which", return_value="/usr/bin/docker"),
            mock.patch("shell.detect.subprocess.run", side_effect=run),
        ):
            st = detect.detect_docker()
        self.assertTrue(st.present)
        self.assertTrue(st.healthy)
        self.assertEqual(st.version, "27.0.0")

    def test_daemon_down(self) -> None:
        ver = mock.Mock(returncode=1, stdout="", stderr="")
        info = mock.Mock(returncode=1, stdout="", stderr="Cannot connect\n")

        def run(args, **kwargs):
            if args[1] == "version":
                return ver
            return info

        with (
            mock.patch("shell.detect.shutil.which", return_value="/usr/bin/docker"),
            mock.patch("shell.detect.subprocess.run", side_effect=run),
        ):
            st = detect.detect_docker()
        self.assertTrue(st.present)
        self.assertFalse(st.healthy)


class DetectWslTests(unittest.TestCase):
    def test_snapshot_keys(self) -> None:
        snap = detect.environment_snapshot()
        self.assertIn("docker", snap)
        self.assertIn("wsl", snap)
        self.assertIn("platform", snap)


if __name__ == "__main__":
    unittest.main()
