"""Smoke the Setup Wizard HTTP API (no live SSH / Docker daemon required)."""

from __future__ import annotations

import json
import os
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from unittest import mock

from shell.wizard_server import serve


class WizardApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self._td = tempfile.TemporaryDirectory()
        self.addCleanup(self._td.cleanup)
        self.env = mock.patch.dict(os.environ, {"IOTGW_DATA_DIR": self._td.name})
        self.env.start()
        self.addCleanup(self.env.stop)
        # Bind ephemeral port
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

    def test_env_and_static(self) -> None:
        env = self._get("/api/wizard/env")
        self.assertIn("docker", env)
        with urllib.request.urlopen(self.base + "/wizard.html", timeout=5) as resp:
            html = resp.read().decode("utf-8")
        self.assertIn("Setup Wizard", html)
        with urllib.request.urlopen(self.base + "/actions.html", timeout=5) as resp:
            html = resp.read().decode("utf-8")
        self.assertIn("Actions", html)
        self.assertIn("Rotate CA", html)
        with urllib.request.urlopen(self.base + "/monitoring.html", timeout=5) as resp:
            mon = resp.read().decode("utf-8")
        self.assertIn("Native Monitoring", mon)
        self.assertIn("monitoring.js", mon)
        with urllib.request.urlopen(self.base + "/monitoring.js", timeout=5) as resp:
            js = resp.read().decode("utf-8")
        self.assertIn("/api/v1/query/summaries", js)

    def test_control_config(self) -> None:
        data = self._get("/api/wizard/control")
        self.assertIn("url", data)
        self.assertTrue(data["url"].startswith("http://127.0.0.1:"))
        self.assertNotIn("actions_path", data)

    def test_checklist_no_auto_apply(self) -> None:
        # Force a fake WSL IP via settings + detect mock
        from shell.paths import load_settings, save_settings

        s = load_settings()
        s["wsl2_ip"] = "172.28.1.5"
        s["monitoring_ip"] = "192.168.1.20"
        save_settings(s)
        data = self._get("/api/wizard/checklist")
        self.assertTrue(data.get("applicable"))
        self.assertFalse(data.get("auto_apply"))
        cmds = [i["command"] for i in data["items"] if i.get("command")]
        self.assertTrue(any("portproxy" in c for c in cmds))
        self.assertTrue(any("advfirewall" in c for c in cmds))
        # Confirm does not execute anything — just flips flag
        conf = self._post("/api/wizard/checklist/confirm", {})
        self.assertTrue(conf["confirmed"])

    def test_nic_select_persists(self) -> None:
        out = self._post(
            "/api/wizard/nics/select",
            {"monitoring_ip": "10.0.0.5", "nic_name": "eth0"},
        )
        self.assertTrue(out["ok"])
        self.assertEqual(out["settings"]["monitoring_ip"], "10.0.0.5")

    def test_install_key_rejects_without_pin(self) -> None:
        req = urllib.request.Request(
            self.base + "/api/wizard/ssh/install-key",
            data=json.dumps(
                {
                    "host": "10.0.0.9",
                    "username": "ubuntu",
                    "password": "secret",
                    "gateway_id": "gw",
                }
            ).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(req, timeout=10)
        self.assertEqual(ctx.exception.code, 400)
        body = json.loads(ctx.exception.read().decode("utf-8"))
        self.assertIn("pin", body.get("error", "").lower())

    def test_services_start_default_skips_streamlit(self) -> None:
        from shell import wizard_server as ws

        calls: list[str] = []

        class _FakeMgr:
            def start_control_service(self, **kwargs):  # noqa: ANN003
                calls.append("control")

                class _P:
                    url = "http://127.0.0.1:9137"

                return _P()

            def start_streamlit(self, **kwargs):  # noqa: ANN003
                calls.append("streamlit")

                class _P:
                    url = "http://127.0.0.1:8501"

                return _P()

            def status(self):
                return {
                    "control": {"running": True},
                    "streamlit": {"running": False},
                }

        with mock.patch.object(ws.STATE, "manager", _FakeMgr()):
            with mock.patch.object(ws, "wait_http", return_value=True):
                out = self._post("/api/wizard/services/start", {})
        self.assertIn("control", calls)
        self.assertNotIn("streamlit", calls)
        self.assertTrue(out["control"]["healthy"])
        self.assertIsNone(out["streamlit"]["url"])

        calls.clear()
        with mock.patch.object(ws.STATE, "manager", _FakeMgr()):
            with mock.patch.object(ws, "wait_http", return_value=True):
                out2 = self._post("/api/wizard/services/start", {"streamlit": True})
        self.assertIn("streamlit", calls)
        self.assertEqual(out2["streamlit"]["url"], "http://127.0.0.1:8501")

    def test_open_streamlit_requires_running(self) -> None:
        req = urllib.request.Request(
            self.base + "/api/wizard/open-streamlit",
            data=b"{}",
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(req, timeout=10)
        self.assertEqual(ctx.exception.code, 400)


if __name__ == "__main__":
    unittest.main()
