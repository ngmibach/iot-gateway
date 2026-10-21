"""Autostart Loki/Prometheus when setup_complete on app launch."""

from __future__ import annotations

import unittest
from unittest import mock

from shell import wizard_server


class TelemetryAutostartTests(unittest.TestCase):
    def test_maybe_autostart_skips_when_setup_incomplete(self) -> None:
        with mock.patch.object(
            wizard_server, "load_settings", return_value={"setup_complete": False}
        ):
            with mock.patch.object(
                wizard_server.STATE, "start_telemetry_job"
            ) as start:
                out = wizard_server.maybe_autostart_telemetry()
        self.assertEqual(out.get("reason"), "setup_incomplete")
        start.assert_not_called()

    def test_maybe_autostart_starts_job_when_setup_complete(self) -> None:
        with mock.patch.object(
            wizard_server, "load_settings", return_value={"setup_complete": True}
        ):
            with mock.patch.object(
                wizard_server.STATE,
                "start_telemetry_job",
                return_value={"started": True, "job": {"state": "running"}},
            ) as start:
                out = wizard_server.maybe_autostart_telemetry()
        start.assert_called_once_with(force=False)
        self.assertTrue(out.get("started"))

    def test_serve_schedules_autostart_when_enabled(self) -> None:
        with mock.patch.object(wizard_server, "maybe_autostart_telemetry") as auto:
            with mock.patch.object(wizard_server, "ThreadingHTTPServer") as httpd_cls:
                httpd_cls.return_value = mock.Mock()
                wizard_server.serve(
                    "127.0.0.1",
                    0,
                    open_browser=False,
                    autostart_telemetry=True,
                )
        # Thread target is maybe_autostart_telemetry; give it a moment.
        import time

        time.sleep(0.05)
        auto.assert_called()


if __name__ == "__main__":
    unittest.main()
