"""Lab panel wizard API smoke (no Docker daemon)."""

from __future__ import annotations

import json
import os
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from unittest import mock

from lab.lifecycle import STORAGE_OVERFLOW_WARNING, FakeSensorStatus
from shell.wizard_server import serve


class LabWizardApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self._td = tempfile.TemporaryDirectory()
        self.addCleanup(self._td.cleanup)
        self.env = mock.patch.dict(os.environ, {"IOTGW_DATA_DIR": self._td.name})
        self.env.start()
        self.addCleanup(self.env.stop)

        self.fake_status = FakeSensorStatus(
            running=False, warning=STORAGE_OVERFLOW_WARNING, detail="idle"
        )

        outer = self

        class _FakeMgr:
            def status(self_inner):
                return outer.fake_status

            def start(self_inner, **kwargs):
                outer.fake_status = FakeSensorStatus(
                    running=True,
                    gateway_ip=kwargs["gateway_ip"],
                    sensors=list(kwargs.get("sensors") or ["sensor1"]),
                    duration_minutes=kwargs.get("duration_minutes", 10),
                    warning=STORAGE_OVERFLOW_WARNING,
                    detail="started",
                )
                return outer.fake_status

            def stop(self_inner, **kwargs):
                outer.fake_status = FakeSensorStatus(
                    running=False, warning=STORAGE_OVERFLOW_WARNING, detail="stopped"
                )
                return outer.fake_status

        self._mgr_patch = mock.patch(
            "shell.wizard_server._lab_manager", return_value=_FakeMgr()
        )
        self._mgr_patch.start()
        self.addCleanup(self._mgr_patch.stop)

        self.server = serve("127.0.0.1", 0, open_browser=False)
        self.port = self.server.server_address[1]
        self.base = f"http://127.0.0.1:{self.port}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self._shutdown)

    def _shutdown(self) -> None:
        self.server.shutdown()
        self.server.server_close()

    def _get(self, path: str) -> dict:
        with urllib.request.urlopen(self.base + path, timeout=5) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def _post(self, path: str, body: dict) -> dict:
        req = urllib.request.Request(
            self.base + path,
            data=json.dumps(body).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def test_lab_html_served(self) -> None:
        with urllib.request.urlopen(self.base + "/lab.html", timeout=5) as resp:
            html = resp.read().decode("utf-8")
        self.assertIn("Storage overflow", html)
        self.assertIn("fake_sensor", html)

    def test_defaults_and_start_stop(self) -> None:
        d = self._get("/api/lab/defaults")
        self.assertIn("warning", d)
        self.assertEqual(d["duration_minutes"], 10)
        st = self._post(
            "/api/lab/fake-sensors/start",
            {
                "gateway_ip": "192.168.1.50",
                "duration_minutes": 5,
                "sensors": ["sensor1"],
            },
        )
        self.assertTrue(st["running"])
        self.assertEqual(st["gateway_ip"], "192.168.1.50")
        self.assertIn("overflow", st["warning"].lower())
        stopped = self._post("/api/lab/fake-sensors/stop", {})
        self.assertFalse(stopped["running"])

    def test_start_requires_gateway_ip(self) -> None:
        req = urllib.request.Request(
            self.base + "/api/lab/fake-sensors/start",
            data=b"{}",
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(req, timeout=5)
        self.assertEqual(ctx.exception.code, 400)


if __name__ == "__main__":
    unittest.main()
