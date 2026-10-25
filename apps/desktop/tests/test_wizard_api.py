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
        self.server = serve("127.0.0.1", 0, open_browser=False, autostart_telemetry=False)
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
        self.assertIn("telemetry", env)
        self.assertEqual(env["telemetry"].get("backend"), "native")
        self.assertFalse(env.get("docker_required", True))
        self.assertIn("setup_complete", env)
        self.assertIn(env.get("entry"), ("wizard", "app"))
        with urllib.request.urlopen(self.base + "/wizard.html", timeout=5) as resp:
            wizard_html = resp.read().decode("utf-8")
        self.assertIn("IoT Gateway Monitor", wizard_html)
        self.assertIn("Install monitoring", wizard_html)
        self.assertIn("Open app", wizard_html)
        self.assertNotIn("id=\"step-nic\"", wizard_html)
        self.assertNotIn("btn-start-svc", wizard_html)
        self.assertNotIn("Full setup", wizard_html)
        self.assertNotIn("Monitoring only", wizard_html)
        self.assertNotIn("uninstall-modal", wizard_html)
        self.assertNotIn("btn-uninstall", wizard_html)
        self.assertIn("first-run", wizard_html)
        self.assertIn("app-shell.js", wizard_html)
        self.assertNotIn('href="actions.html"', wizard_html)
        self.assertNotIn('href="monitoring.html"', wizard_html)
        self.assertNotIn('href="admin.html"', wizard_html)
        self.assertNotIn("lab.html", wizard_html)
        with urllib.request.urlopen(self.base + "/gateways.html", timeout=5) as resp:
            gw_html = resp.read().decode("utf-8")
        self.assertIn("Registration", gw_html)
        self.assertIn("Clean up", gw_html)
        self.assertIn("gateways.js", gw_html)
        self.assertIn("app-shell.js", gw_html)
        with urllib.request.urlopen(self.base + "/settings.html", timeout=5) as resp:
            settings_html = resp.read().decode("utf-8")
        self.assertIn("Remove", settings_html)
        self.assertIn("monitoring panel", settings_html.lower())
        self.assertIn("Loki and Prometheus", settings_html)
        self.assertIn("Local app data", settings_html)
        self.assertNotIn("Gateway only", settings_html)
        self.assertNotIn("Gateways → Clean up", settings_html)
        self.assertIn("settings.js", settings_html)
        with urllib.request.urlopen(self.base + "/actions.html", timeout=5) as resp:
            actions_html = resp.read().decode("utf-8")
        self.assertIn("Control Plane", actions_html)
        self.assertIn("Registration", actions_html)
        self.assertIn("Registered sensors", actions_html)
        self.assertIn("Registration · View · Simulate", actions_html)
        self.assertIn('data-action="simulate"', actions_html)
        self.assertIn("Find sensor", actions_html)
        self.assertIn("Create fake sensor", actions_html)
        self.assertIn('id="host-list"', actions_html)
        self.assertIn('id="btn-find-sensor"', actions_html)
        self.assertIn('id="btn-create-fake"', actions_html)
        self.assertIn('id="btn-manual-ip"', actions_html)
        self.assertIn('id="reg-form"', actions_html)
        self.assertIn('id="fake-form"', actions_html)
        self.assertIn('id="fake-user"', actions_html)
        self.assertIn('id="fake-pass"', actions_html)
        self.assertNotIn('id="fake-interval"', actions_html)
        self.assertNotIn('id="fake-payload"', actions_html)
        self.assertIn("Set rate and payload in Simulate", actions_html)
        self.assertIn('id="btn-fake-create"', actions_html)
        self.assertIn('id="btn-fake-cancel"', actions_html)
        self.assertIn('id="view-type-badge"', actions_html)
        self.assertIn('id="view-fake-meta"', actions_html)
        self.assertIn('id="btn-open-simulate"', actions_html)
        self.assertIn("Open Simulate", actions_html)
        self.assertIn('id="panel-simulate"', actions_html)
        self.assertIn('id="sim-device"', actions_html)
        self.assertIn('id="sim-interval"', actions_html)
        self.assertIn('id="sim-topic"', actions_html)
        self.assertIn('id="sim-payload"', actions_html)
        self.assertIn('id="btn-sim-start"', actions_html)
        self.assertIn('id="btn-sim-stop"', actions_html)
        self.assertIn('id="btn-sim-apply"', actions_html)
        self.assertIn("Omit client certificate", actions_html)
        self.assertIn("Wrong client certificate", actions_html)
        self.assertIn("Skip payload encryption", actions_html)
        self.assertIn("Bad encryption", actions_html)
        self.assertIn("Wrong MQTT password", actions_html)
        self.assertIn("Wrong topic", actions_html)
        self.assertIn('id="ca-modal"', actions_html)
        self.assertIn("Gateway CA passphrase", actions_html)
        self.assertIn('id="fake-ca-block"', actions_html)
        self.assertIn('id="fake-ca-auto"', actions_html)
        self.assertIn('id="fake-ca-sudo"', actions_html)
        self.assertIn('id="fake-ca"', actions_html)
        self.assertIn('id="reg-ca-block"', actions_html)
        self.assertIn('id="reg-ca-auto"', actions_html)
        self.assertIn("Generate CA passphrase", actions_html)
        self.assertIn("I am confirming that I want to delete this", actions_html)
        self.assertIn('id="btn-view-update"', actions_html)
        self.assertIn('id="btn-view-reissue"', actions_html)
        self.assertIn("Re-issue cert", actions_html)
        self.assertNotIn('id="view-ca"', actions_html)
        self.assertNotIn("Rotate CA", actions_html)
        self.assertNotIn('id="ctrl-url"', actions_html)
        self.assertNotIn('id="ctrl-token"', actions_html)
        self.assertIn("app-shell.js", actions_html)
        self.assertIn("actions.js", actions_html)
        with urllib.request.urlopen(self.base + "/actions.js", timeout=5) as resp:
            ajs = resp.read().decode("utf-8")
        self.assertIn("/devices/discover", ajs)
        self.assertIn("/devices/fake", ajs)
        self.assertIn("is_fake", ajs)
        self.assertIn("/reissue-cert", ajs)
        self.assertIn("/api/wizard/secrets/ca-status", ajs)
        self.assertIn("/api/wizard/secrets/ca", ajs)
        self.assertIn("/api/wizard/secrets/ca-ensure", ajs)
        self.assertIn("/api/wizard/secrets/sudo-status", ajs)
        self.assertIn("sudoStatusPresent", ajs)
        self.assertIn("ensureCaFromRegistration", ajs)
        self.assertIn("btn-find-sensor", ajs)
        self.assertIn("btn-create-fake", ajs)
        self.assertIn("findSensors", ajs)
        self.assertIn("createFakeDevice", ajs)
        self.assertIn("showFakeForm", ajs)
        self.assertIn("refreshFakeDevices", ajs)
        self.assertIn("applySimConfig", ajs)
        self.assertIn("simStartStop", ajs)
        self.assertIn("omit_client_cert", ajs)
        self.assertIn("withCaRetry", ajs)
        with urllib.request.urlopen(self.base + "/monitoring.html", timeout=5) as resp:
            mon = resp.read().decode("utf-8")
        self.assertIn("Monitoring", mon)
        self.assertIn("Gateway Metric", mon)
        self.assertIn("Gateway Activities", mon)
        self.assertIn("Applications", mon)
        self.assertIn('id="raspi-app-metrics"', mon)
        self.assertIn('id="gw-sensor-detail"', mon)
        self.assertIn('id="gw-sensor-tabs"', mon)
        self.assertIn('id="chart-sensor_kafka"', mon)
        self.assertIn("Kafka topic", mon)
        self.assertNotIn(">Containers<", mon)
        self.assertIn("monitoring.js", mon)
        self.assertIn("app-shell.js", mon)
        with urllib.request.urlopen(self.base + "/monitoring.js", timeout=5) as resp:
            mjs = resp.read().decode("utf-8")
        self.assertIn("messages_per_sec", mjs)
        self.assertIn("renderSensorTabs", mjs)
        self.assertIn("kafka_topic", mjs)
        self.assertIn("Name only", mjs)
        self.assertIn("is_fake", mjs)
        self.assertIn('"Type"', mjs)
        self.assertIn("typeBadgeHtml", mjs)
        self.assertIn("badge fake", mjs)
        with urllib.request.urlopen(self.base + "/app-shell.js", timeout=5) as resp:
            shell = resp.read().decode("utf-8")
        self.assertIn("Monitoring", shell)
        self.assertIn("Gateways", shell)
        self.assertIn("Registration", shell)
        self.assertIn("Clean up", shell)
        self.assertIn("Settings", shell)
        self.assertIn("gateways.html", shell)
        self.assertIn("settings.html", shell)
        self.assertIn("Remove", shell)
        self.assertNotIn("wizard.html", shell)
        with urllib.request.urlopen(self.base + "/wizard.js", timeout=5) as resp:
            wjs = resp.read().decode("utf-8")
        self.assertIn("background: true", wjs)
        self.assertNotIn("iotgw_setup_path", wjs)
        self.assertNotIn("/api/wizard/uninstall", wjs)
        self.assertIn("/api/wizard/setup/complete", wjs)
        with urllib.request.urlopen(self.base + "/settings.js", timeout=5) as resp:
            sjs = resp.read().decode("utf-8")
        self.assertIn("/api/wizard/uninstall", sjs)
        self.assertIn("monitoring: true", sjs)
        with urllib.request.urlopen(self.base + "/gateways.js", timeout=5) as resp:
            gjs = resp.read().decode("utf-8")
        self.assertIn("/api/wizard/provision", gjs)
        self.assertIn("monitoring: false", gjs)
        self.assertIn("/api/wizard/settings/gateway", gjs)
        self.assertIn("/api/wizard/discover/gateways", gjs)
        self.assertIn("/api/wizard/firewall/apply", gjs)
        self.assertIn("/api/wizard/ssh/fetch-host-key", gjs)
        self.assertIn("/api/wizard/ssh/pin-host-key", gjs)
        self.assertIn("/api/wizard/ssh/install-key", gjs)
        self.assertNotIn("checklist-wrap", gjs)
        self.assertIn("Find gateway", gjs)
        self.assertIn("host-list", gjs)
        with urllib.request.urlopen(self.base + "/gateways.html", timeout=5) as resp:
            gw_html2 = resp.read().decode("utf-8")
        self.assertIn("Find gateway", gw_html2)
        self.assertIn('id="host-list"', gw_html2)
        self.assertIn('id="reg-install"', gw_html2)
        self.assertIn("field-help", gw_html2)
        self.assertIn("Sudo password", gw_html2)
        self.assertIn('id="ca-auto"', gw_html2)
        self.assertIn("Generate CA passphrase", gw_html2)
        self.assertIn("Creates a signing password for this gateway.", gw_html2)
        self.assertIn('id="ca-pass"', gw_html2)
        self.assertIn("Signing password for this gateway.", gw_html2)
        self.assertIn("generate_ca_passphrase", gjs)
        self.assertIn("Login name for the gateway.", gw_html2)
        self.assertIn("Configure a registered gateway.", gw_html2)
        self.assertIn('id="cfg-pass"', gw_html2)
        self.assertIn('id="cu-gateway-id"', gw_html2)
        self.assertIn('id="cu-sudo"', gw_html2)
        self.assertNotIn("Scan LAN for SSH", gw_html2)
        self.assertNotIn("Apply firewall", gw_html2)
        self.assertNotIn('id="nic-select"', gw_html2)
        self.assertNotIn('id="cfg-nic-select"', gw_html2)
        self.assertNotIn('id="cfg-port"', gw_html2)
        self.assertNotIn("This PC LAN", gw_html2)
        self.assertNotIn('id="cu-list"', gw_html2)
        self.assertNotIn('id="cu-summary"', gw_html2)
        self.assertNotIn("btn-fetch-hk", gw_html2)
        self.assertNotIn("checklist-wrap", gw_html2)
        self.assertNotIn('id="gateway-ip"', gw_html2)
        with urllib.request.urlopen(self.base + "/monitoring.js", timeout=5) as resp:
            js = resp.read().decode("utf-8")
        self.assertIn("/api/v1/query/summaries", js)
        self.assertIn("Gateway Metric", js)
        with urllib.request.urlopen(self.base + "/splash.html", timeout=5) as resp:
            splash = resp.read().decode("utf-8")
        self.assertIn("setup_complete", splash)
        self.assertIn("monitoring.html#metric", splash)

    def test_setup_complete_marks_entry_app(self) -> None:
        env = self._get("/api/wizard/env")
        self.assertFalse(env.get("setup_complete"))
        self.assertEqual(env.get("entry"), "wizard")
        out = self._post("/api/wizard/setup/complete", {})
        self.assertTrue(out.get("ok"))
        self.assertTrue(out.get("setup_complete"))
        env2 = self._get("/api/wizard/env")
        self.assertTrue(env2.get("setup_complete"))
        self.assertEqual(env2.get("entry"), "app")

    def test_settings_gateway_persists_ssh(self) -> None:
        from shell.paths import load_settings

        out = self._post(
            "/api/wizard/settings/gateway",
            {
                "gateway_id": "gw-lab",
                "gateway_ip": "192.168.1.60",
                "ssh_host": "192.168.1.60",
                "ssh_user": "pi",
                "ssh_port": 2222,
            },
        )
        self.assertTrue(out.get("ok"))
        s = load_settings()
        self.assertEqual(s.get("default_gateway_id"), "gw-lab")
        self.assertEqual(s.get("ssh_host"), "192.168.1.60")
        self.assertEqual(s.get("ssh_user"), "pi")
        self.assertEqual(s.get("ssh_port"), 2222)

    def test_ca_secret_status_put_delete(self) -> None:
        from shell import keyring_store

        with mock.patch.object(keyring_store, "_keyring_usable", return_value=False):
            missing = self._get("/api/wizard/secrets/ca-status?gateway_id=gw1")
            self.assertFalse(missing.get("present"))

            put_req = urllib.request.Request(
                self.base + "/api/wizard/secrets/ca",
                data=json.dumps(
                    {"gateway_id": "gw1", "ca_passphrase": "correct-horse"}
                ).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="PUT",
            )
            with urllib.request.urlopen(put_req, timeout=10) as resp:
                put_body = json.loads(resp.read().decode("utf-8"))
            self.assertTrue(put_body.get("ok"))
            self.assertTrue(put_body.get("present"))

            present = self._get("/api/wizard/secrets/ca-status?gateway_id=gw1")
            self.assertTrue(present.get("present"))
            # Status must never echo the secret.
            self.assertNotIn("ca_passphrase", present)
            self.assertNotIn("correct-horse", json.dumps(present))

            bad = urllib.request.Request(
                self.base + "/api/wizard/secrets/ca",
                data=json.dumps(
                    {"gateway_id": "gw1", "ca_passphrase": "admin"}
                ).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="PUT",
            )
            with self.assertRaises(urllib.error.HTTPError) as ctx:
                urllib.request.urlopen(bad, timeout=10)
            self.assertEqual(ctx.exception.code, 400)

            del_req = urllib.request.Request(
                self.base + "/api/wizard/secrets/ca?gateway_id=gw1",
                method="DELETE",
            )
            with urllib.request.urlopen(del_req, timeout=10) as resp:
                del_body = json.loads(resp.read().decode("utf-8"))
            self.assertTrue(del_body.get("ok"))
            self.assertFalse(del_body.get("present"))
            after = self._get("/api/wizard/secrets/ca-status?gateway_id=gw1")
            self.assertFalse(after.get("present"))

            # ca-ensure: generate from sudo + device password when absent.
            ensure_req = urllib.request.Request(
                self.base + "/api/wizard/secrets/ca-ensure",
                data=json.dumps(
                    {
                        "gateway_id": "gw1",
                        "generate": True,
                        "sudo_password": "s3cret-sudo",
                        "device_password": "sensor-pass-1",
                    }
                ).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(ensure_req, timeout=10) as resp:
                ensured = json.loads(resp.read().decode("utf-8"))
            self.assertTrue(ensured.get("ok"))
            self.assertTrue(ensured.get("created"))
            self.assertEqual(ensured.get("source"), "generated")
            self.assertTrue(ensured.get("present"))
            self.assertNotIn("ca_passphrase", ensured)
            self.assertNotIn("s3cret-sudo", json.dumps(ensured))

            # Second ensure reuses keyring (no recreate).
            ensure2 = urllib.request.Request(
                self.base + "/api/wizard/secrets/ca-ensure",
                data=json.dumps(
                    {
                        "gateway_id": "gw1",
                        "generate": True,
                        "sudo_password": "other",
                    }
                ).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(ensure2, timeout=10) as resp:
                again = json.loads(resp.read().decode("utf-8"))
            self.assertFalse(again.get("created"))
            self.assertEqual(again.get("source"), "keyring")

    def test_sudo_secret_status_put_delete_and_ca_ensure_fallback(self) -> None:
        from shell import keyring_store

        with mock.patch.object(keyring_store, "_keyring_usable", return_value=False):
            missing = self._get("/api/wizard/secrets/sudo-status?gateway_id=gw1")
            self.assertFalse(missing.get("present"))

            put_req = urllib.request.Request(
                self.base + "/api/wizard/secrets/sudo",
                data=json.dumps(
                    {"gateway_id": "gw1", "sudo_password": "login-same-as-sudo"}
                ).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="PUT",
            )
            with urllib.request.urlopen(put_req, timeout=10) as resp:
                put_body = json.loads(resp.read().decode("utf-8"))
            self.assertTrue(put_body.get("ok"))
            self.assertTrue(put_body.get("present"))
            self.assertNotIn("login-same-as-sudo", json.dumps(put_body))

            present = self._get("/api/wizard/secrets/sudo-status?gateway_id=gw1")
            self.assertTrue(present.get("present"))
            self.assertNotIn("sudo_password", present)

            # ca-ensure generate with no body sudo uses keyring sudo.
            keyring_store.delete_secret("gw1", kind="ca")
            ensure_req = urllib.request.Request(
                self.base + "/api/wizard/secrets/ca-ensure",
                data=json.dumps(
                    {
                        "gateway_id": "gw1",
                        "generate": True,
                        "device_password": "sensor-pass-1",
                    }
                ).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(ensure_req, timeout=10) as resp:
                ensured = json.loads(resp.read().decode("utf-8"))
            self.assertTrue(ensured.get("created"))
            self.assertEqual(ensured.get("source"), "generated")
            self.assertTrue(keyring_store.get_secret("gw1", kind="ca"))

            # settings/gateway password also stores sudo.
            keyring_store.delete_secret("gw1", kind="sudo")
            settings_req = urllib.request.Request(
                self.base + "/api/wizard/settings/gateway",
                data=json.dumps(
                    {
                        "gateway_id": "gw1",
                        "ssh_host": "192.168.1.50",
                        "ssh_user": "admin",
                        "password": "settings-sudo-pw",
                    }
                ).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(settings_req, timeout=10) as resp:
                settings_body = json.loads(resp.read().decode("utf-8"))
            self.assertTrue(settings_body.get("ok"))
            self.assertEqual(
                keyring_store.get_secret("gw1", kind="sudo"), "settings-sudo-pw"
            )
            self.assertNotIn("settings-sudo-pw", json.dumps(settings_body))

            del_req = urllib.request.Request(
                self.base + "/api/wizard/secrets/sudo?gateway_id=gw1",
                method="DELETE",
            )
            with urllib.request.urlopen(del_req, timeout=10) as resp:
                del_body = json.loads(resp.read().decode("utf-8"))
            self.assertTrue(del_body.get("ok"))
            self.assertFalse(del_body.get("present"))

    def test_control_config(self) -> None:
        data = self._get("/api/wizard/control")
        self.assertIn("url", data)
        self.assertTrue(data["url"].startswith("http://127.0.0.1:"))
        self.assertNotIn("actions_path", data)

    def test_checklist_windows_native_no_portproxy(self) -> None:
        from unittest import mock

        from shell.paths import load_settings, save_settings

        s = load_settings()
        s["monitoring_ip"] = "192.168.1.20"
        save_settings(s)
        with mock.patch("shell.detect.operator_runtime", return_value="windows"):
            data = self._get("/api/wizard/checklist")
        self.assertTrue(data.get("applicable"))
        self.assertEqual(data.get("path"), "windows_native")
        self.assertTrue(data.get("auto_apply"))
        cmds = [i["command"] for i in data["items"] if i.get("command")]
        self.assertTrue(any("advfirewall" in c for c in cmds))
        self.assertFalse(any("portproxy" in c for c in cmds))
        conf = self._post("/api/wizard/checklist/confirm", {})
        self.assertTrue(conf["confirmed"])

    def test_discover_gateways_requires_monitoring_ip(self) -> None:
        req = urllib.request.Request(
            self.base + "/api/wizard/discover/gateways",
            data=b"{}",
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(req, timeout=10)
        self.assertEqual(ctx.exception.code, 400)

    def test_discover_gateways_returns_hosts(self) -> None:
        from unittest import mock

        from shell.paths import save_settings

        save_settings({"monitoring_ip": "192.168.1.20"})
        with mock.patch(
            "shell.discover.scan_ssh_hosts",
            return_value=[
                {"ip": "192.168.1.50", "port": 22, "open": True},
                {"ip": "192.168.1.60", "port": 22, "open": True},
            ],
        ):
            data = self._post("/api/wizard/discover/gateways", {})
        self.assertTrue(data.get("ok"))
        self.assertEqual(data.get("count"), 2)
        ips = {h["ip"] for h in data.get("hosts") or []}
        self.assertEqual(ips, {"192.168.1.50", "192.168.1.60"})

    def test_firewall_apply_skips_non_windows(self) -> None:
        from unittest import mock

        with mock.patch("shell.detect.operator_runtime", return_value="linux"):
            with mock.patch("shell.firewall_apply.is_elevated", return_value=None):
                data = self._post("/api/wizard/firewall/apply", {})
        self.assertTrue(data.get("ok"))
        self.assertTrue(data.get("skipped"))
        self.assertFalse(data.get("applicable"))

    def test_firewall_apply_requires_admin_on_windows(self) -> None:
        from unittest import mock

        with mock.patch("shell.detect.operator_runtime", return_value="windows"):
            with mock.patch("shell.firewall_apply.is_elevated", return_value=False):
                req = urllib.request.Request(
                    self.base + "/api/wizard/firewall/apply",
                    data=b"{}",
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                with self.assertRaises(urllib.error.HTTPError) as ctx:
                    urllib.request.urlopen(req, timeout=10)
        self.assertEqual(ctx.exception.code, 403)

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

    def test_telemetry_ensure_background_job(self) -> None:
        from shell import wizard_server as ws

        class _Snap:
            ready = False
            binaries_present = True
            loki_running = False
            prometheus_running = False
            detail = "waiting"
            progress = "Downloading (10%)"

        class _FakeTel:
            def snapshot(self):
                return _Snap()

            def ensure_binaries(self, force=False):  # noqa: ANN001
                return {}

            def start(self, **kwargs):  # noqa: ANN003
                import time

                time.sleep(0.15)

                class _St:
                    running = True
                    detail = "Loki and Prometheus are running."
                    loki = None
                    prometheus = None

                _Snap.ready = True
                _Snap.loki_running = True
                _Snap.prometheus_running = True
                _Snap.detail = "Loki and Prometheus are running."
                return _St()

        with mock.patch.object(ws.STATE, "_telemetry", _FakeTel()):
            # Reset job state between tests (module-level STATE).
            with ws.STATE.lock:
                ws.STATE._telemetry_job = {
                    "state": "idle",
                    "detail": "",
                    "error": None,
                }
            out = self._post(
                "/api/wizard/telemetry/ensure",
                {"background": True},
            )
            self.assertTrue(out.get("background"))
            self.assertIn(out.get("job", {}).get("state"), ("running", "ok"))

            import time

            deadline = time.time() + 5
            final = None
            while time.time() < deadline:
                final = self._get("/api/wizard/telemetry/status")
                if final.get("job", {}).get("state") in ("ok", "error"):
                    break
                time.sleep(0.05)
            self.assertIsNotNone(final)
            assert final is not None
            self.assertEqual(final["job"]["state"], "ok")
            self.assertTrue(final.get("ready"))

    def test_services_start_control_only(self) -> None:
        from shell import wizard_server as ws

        calls: list[str] = []

        class _FakeMgr:
            def start_control_service(self, **kwargs):  # noqa: ANN003
                calls.append("control")

                class _P:
                    url = "http://127.0.0.1:9137"

                return _P()

            def status(self):
                return {"control": {"running": True}}

        with mock.patch.object(ws.STATE, "manager", _FakeMgr()):
            with mock.patch.object(ws, "wait_http", return_value=True):
                out = self._post("/api/wizard/services/start", {})
        self.assertIn("control", calls)
        self.assertTrue(out["control"]["healthy"])
        self.assertNotIn("streamlit", out)

    def test_proxy_control_injects_api_token(self) -> None:
        from shell import wizard_server as ws

        captured: dict = {}
        real_urlopen = urllib.request.urlopen

        class _Resp:
            status = 200
            headers = {"Content-Type": "application/json"}

            def read(self) -> bytes:
                return b'{"ok":true}'

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return None

        def fake_urlopen(req, timeout=30):  # noqa: ANN001
            url = req if isinstance(req, str) else req.full_url
            # Wizard→control proxy only; pass through the test→wizard request.
            if ":9137" not in url:
                return real_urlopen(req, timeout=timeout)
            captured["url"] = url
            captured["headers"] = dict(req.headers)
            captured["method"] = req.get_method()
            return _Resp()

        with mock.patch.dict(os.environ, {"IOTGW_API_TOKEN": "secret-token"}):
            with mock.patch.object(ws.urllib.request, "urlopen", fake_urlopen):
                with urllib.request.urlopen(
                    self.base + "/api/v1/gateways", timeout=5
                ) as resp:
                    body = json.loads(resp.read().decode("utf-8"))
        self.assertEqual(body, {"ok": True})
        self.assertIn("http://127.0.0.1:9137/api/v1/gateways", captured["url"])
        headers = {k.lower(): v for k, v in captured["headers"].items()}
        self.assertEqual(headers.get("x-api-token"), "secret-token")

    def test_uninstall_monitoring_without_gateway(self) -> None:
        from pathlib import Path

        from shell import wizard_server as ws
        from shell.paths import data_dir

        tel_root = Path(self._td.name) / "telemetry"
        tel_root.mkdir(parents=True)
        (tel_root / "bin").mkdir()
        (tel_root / "bin" / "loki").write_text("x", encoding="utf-8")
        (Path(self._td.name) / "settings.json").write_text(
            '{"monitoring_ip":"192.168.1.20"}', encoding="utf-8"
        )

        class _FakeTel:
            def stop(self):
                return None

            def uninstall(self):
                import shutil

                if tel_root.is_dir():
                    shutil.rmtree(tel_root)
                return {"ok": True, "root": str(tel_root), "removed": ["bin"], "errors": []}

        class _FakeMgr:
            def stop_all(self):
                return None

        with mock.patch.object(ws.STATE, "_telemetry", _FakeTel()):
            with mock.patch.object(ws.STATE, "manager", _FakeMgr()):
                out = self._post(
                    "/api/wizard/uninstall",
                    {"monitoring": True, "gateway": True},
                )
        self.assertTrue(out.get("ok"))
        self.assertIsNotNone(out.get("monitoring"))
        self.assertIsNotNone(out.get("app_data"))
        self.assertFalse(tel_root.exists())
        # wipe recreates empty data dir
        self.assertTrue(data_dir().is_dir())

    def test_uninstall_monitoring_forces_all_gateways(self) -> None:
        """Monitoring wipe auto-includes every registered gateway (needs sudo)."""
        from pathlib import Path

        from shell.paths import save_settings

        save_settings(
            {
                "ssh_host": "192.168.1.50",
                "ssh_user": "ubuntu",
                "gateway_ip": "192.168.1.50",
                "default_gateway_id": "gateway",
            }
        )
        from shell import uninstall as uninstall_mod

        # monitoring=True with gateway=False still couples and needs sudo for SSH.
        with self.assertRaises(uninstall_mod.UninstallError) as ctx:
            uninstall_mod.run_uninstall(
                gateway=False,
                monitoring=True,
                stop_telemetry=lambda: None,
                stop_services=lambda: None,
                telemetry_uninstall=lambda: {"ok": True},
            )
        self.assertIn("sudo password", str(ctx.exception).lower())

        # API: monitoring alone → gateway forced → 409 without sudo.
        req = urllib.request.Request(
            self.base + "/api/wizard/uninstall",
            data=json.dumps({"monitoring": True}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with self.assertRaises(urllib.error.HTTPError) as http_ctx:
            urllib.request.urlopen(req, timeout=10)
        self.assertEqual(http_ctx.exception.code, 409)
        self.assertTrue(Path(self._td.name).is_dir())

    def test_uninstall_targets_lists_registry_gateways(self) -> None:
        from registry.registry import Registry
        from shell.paths import ensure_data_dir

        reg = Registry(str(ensure_data_dir() / "registry.sqlite"))
        try:
            reg.upsert_gateway(
                "gw-a",
                host="192.168.1.10",
                ssh_user="ubuntu",
                install_root="/opt/iot-gateway-agent",
                fingerprint="aa",
            )
            reg.upsert_gateway(
                "gw-b",
                host="192.168.1.11",
                ssh_user="ubuntu",
                install_root="/opt/iot-gateway-agent",
                fingerprint="bb",
            )
        finally:
            reg.close()
        data = self._get("/api/wizard/uninstall/targets")
        ids = {g["id"] for g in data.get("gateways") or []}
        self.assertIn("gw-a", ids)
        self.assertIn("gw-b", ids)
        self.assertIn("monitoring_hint", data)

    def test_uninstall_monitoring_removes_all_registry_gateways(self) -> None:
        from pathlib import Path
        from unittest import mock

        from registry.registry import Registry
        from shell import uninstall as uninstall_mod
        from shell.paths import ensure_data_dir

        reg_path = ensure_data_dir() / "registry.sqlite"
        reg = Registry(str(reg_path))
        try:
            reg.upsert_gateway(
                "gw-a",
                host="192.168.1.10",
                ssh_user="ubuntu",
                install_root="/opt/iot-gateway-agent",
                fingerprint="aa",
            )
            reg.upsert_gateway(
                "gw-b",
                host="192.168.1.11",
                ssh_user="ubuntu",
                install_root="/opt/iot-gateway-agent",
                fingerprint="bb",
            )
        finally:
            reg.close()

        with mock.patch.object(
            uninstall_mod,
            "uninstall_gateway_over_ssh",
            return_value=["stopped"],
        ) as ssh_un:
            with mock.patch.object(uninstall_mod, "clear_local_secrets"):
                out = uninstall_mod.run_uninstall(
                    gateway=False,
                    monitoring=True,
                    sudo_password="secret",
                    stop_telemetry=lambda: None,
                    stop_services=lambda: None,
                    telemetry_uninstall=lambda: {
                        "ok": True,
                        "root": str(Path(self._td.name) / "telemetry"),
                        "errors": [],
                    },
                )
        self.assertEqual(ssh_un.call_count, 2)
        self.assertTrue(out.get("ok"))
        self.assertEqual(sorted(out["gateway"]["ids"]), ["gw-a", "gw-b"])
        # wipe_app_data removes registry; re-open should be empty / missing.
        if reg_path.is_file():
            reg2 = Registry(str(reg_path))
            try:
                self.assertEqual(reg2.list_gateways(), [])
            finally:
                reg2.close()

    def test_uninstall_gateway_only_keeps_telemetry(self) -> None:
        from pathlib import Path

        from shell import uninstall as uninstall_mod
        from shell.paths import save_settings

        tel = Path(self._td.name) / "telemetry" / "bin"
        tel.mkdir(parents=True)
        (tel / "loki").write_text("x", encoding="utf-8")
        save_settings(
            {
                "ssh_host": "192.168.1.50",
                "ssh_user": "ubuntu",
                "ssh_port": 22,
                "gateway_ip": "192.168.1.50",
                "default_gateway_id": "gateway",
                "monitoring_ip": "192.168.1.20",
            }
        )
        with mock.patch.object(
            uninstall_mod,
            "uninstall_gateway_over_ssh",
            return_value=["systemd stopped"],
        ) as ssh_un:
            with mock.patch.object(
                uninstall_mod, "remove_gateway_from_registry", return_value=True
            ):
                with mock.patch.object(uninstall_mod, "clear_local_secrets"):
                    out = uninstall_mod.run_uninstall(
                        gateway=True,
                        monitoring=False,
                        sudo_password="secret",
                        stop_telemetry=lambda: None,
                        stop_services=lambda: None,
                        telemetry_uninstall=lambda: (_ for _ in ()).throw(
                            AssertionError("must not wipe telemetry")
                        ),
                    )
        ssh_un.assert_called_once()
        self.assertTrue(out["ok"])
        self.assertTrue((tel / "loki").is_file())


if __name__ == "__main__":
    unittest.main()
