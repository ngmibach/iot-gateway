"""Windows subprocess helpers for telemetry daemons."""

from __future__ import annotations

import unittest
from unittest import mock

from telemetry import winproc


class TelemetryWinprocTests(unittest.TestCase):
    def test_daemon_popen_kwargs_posix_uses_session(self) -> None:
        with mock.patch.object(winproc.os, "name", "posix"):
            self.assertEqual(winproc.daemon_popen_kwargs(), {"start_new_session": True})

    def test_daemon_popen_kwargs_windows_breaks_away(self) -> None:
        with mock.patch.object(winproc.os, "name", "nt"):
            kwargs = winproc.daemon_popen_kwargs()
        flags = kwargs["creationflags"]
        self.assertTrue(flags & winproc._CREATE_NO_WINDOW)
        self.assertTrue(flags & winproc._CREATE_NEW_PROCESS_GROUP)
        self.assertTrue(flags & winproc._CREATE_BREAKAWAY_FROM_JOB)


if __name__ == "__main__":
    unittest.main()
