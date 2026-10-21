"""Windows hidden-subprocess helper."""

from __future__ import annotations

import subprocess
import unittest
from unittest import mock

from shell import winproc


class WinprocTests(unittest.TestCase):
    def test_hidden_kwargs_empty_off_windows(self) -> None:
        with mock.patch.object(winproc.os, "name", "posix"):
            self.assertEqual(winproc.hidden_kwargs(), {})

    def test_hidden_kwargs_create_no_window_on_windows(self) -> None:
        with mock.patch.object(winproc.os, "name", "nt"):
            kwargs = winproc.hidden_kwargs()
        self.assertIn("creationflags", kwargs)
        self.assertEqual(
            kwargs["creationflags"],
            getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )


if __name__ == "__main__":
    unittest.main()
