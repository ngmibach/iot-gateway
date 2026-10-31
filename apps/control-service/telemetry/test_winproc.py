"""Windows subprocess helpers for telemetry daemons."""

from __future__ import annotations

import unittest
from unittest import mock

from telemetry import winproc


class TelemetryWinprocTests(unittest.TestCase):
    def setUp(self) -> None:
        winproc._breakaway_allowed = None
        winproc._use_wmi_detach = None

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

    def test_daemon_popen_kwargs_can_skip_breakaway(self) -> None:
        with mock.patch.object(winproc.os, "name", "nt"):
            kwargs = winproc.daemon_popen_kwargs(breakaway=False)
        flags = kwargs["creationflags"]
        self.assertTrue(flags & winproc._CREATE_NO_WINDOW)
        self.assertTrue(flags & winproc._CREATE_NEW_PROCESS_GROUP)
        self.assertFalse(flags & winproc._CREATE_BREAKAWAY_FROM_JOB)

    def test_popen_daemon_uses_wmi_when_breakaway_denied(self) -> None:
        def fake_popen(*_a, **kw):
            flags = int(kw.get("creationflags", 0))
            if flags & winproc._CREATE_BREAKAWAY_FROM_JOB:
                raise PermissionError(5, "Access is denied")
            raise AssertionError("should not retry plain Popen after breakaway deny")

        with (
            mock.patch.object(winproc.os, "name", "nt"),
            mock.patch.object(winproc.subprocess, "Popen", side_effect=fake_popen),
            mock.patch.object(winproc, "_wmi_create", return_value=4242) as wmi,
        ):
            proc = winproc.popen_daemon(["loki.exe", "-config.file=x"])
        self.assertIsInstance(proc, winproc._WmiProc)
        self.assertEqual(proc.pid, 4242)
        wmi.assert_called_once()
        self.assertIs(winproc._breakaway_allowed, False)
        self.assertIs(winproc._use_wmi_detach, True)

    def test_quote_and_cmdline(self) -> None:
        self.assertEqual(winproc._quote_win_arg("loki.exe"), "loki.exe")
        self.assertIn("\\", winproc._quote_win_arg(r"C:\path with space\a.exe"))
        self.assertTrue(winproc._cmdline(["a", "b c"]).endswith('"b c"'))


if __name__ == "__main__":
    unittest.main()
