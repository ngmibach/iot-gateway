"""Support-bundle redaction tests — no secrets/private PEMs in export."""

from __future__ import annotations

import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from api.settings import Settings
from registry.registry import Registry
from support import (
    REDACTED,
    bundle_contains_forbidden,
    collect_bundle_payload,
    redact_string,
    redact_value,
    settings_public,
    write_support_bundle,
)

FAKE_PEM = """-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7
-----END PRIVATE KEY-----"""

FAKE_CERT = """-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJAKH
-----END CERTIFICATE-----"""


class RedactHelpersTests(unittest.TestCase):
    def test_redact_private_pem_and_bearer(self) -> None:
        text = f"key={FAKE_PEM}\nAuthorization: Bearer super-secret-token\n"
        out = redact_string(text)
        self.assertNotIn("BEGIN PRIVATE KEY", out)
        self.assertNotIn("super-secret-token", out)
        self.assertIn(REDACTED, out)

    def test_redact_free_text_assignments_not_field_names(self) -> None:
        text = "\n".join(
            [
                "export IOTGW_CA_PASSPHRASE=super-secret",
                "IOTGW_API_TOKEN=live-api-token",
                "IOTGW_SSH_PASSWORD=ssh-secret",
                "password=hunter2",
                "token: abc.def",
                "password_auth_enabled=1",
                "gateway password_auth_enabled flag ok",
                "-passin pass:on-argv",
                "-passout env:CA_PASS",
            ]
        )
        out = redact_string(text)
        self.assertNotIn("super-secret", out)
        self.assertNotIn("live-api-token", out)
        self.assertNotIn("ssh-secret", out)
        self.assertNotIn("hunter2", out)
        self.assertNotIn("abc.def", out)
        self.assertNotIn("on-argv", out)
        self.assertIn(f"IOTGW_CA_PASSPHRASE={REDACTED}", out)
        self.assertIn(f"password={REDACTED}", out)
        # Boolean diagnostic must survive (word-boundary on password=).
        self.assertIn("password_auth_enabled=1", out)

    def test_redact_nested_secret_keys(self) -> None:
        raw = {
            "host": "192.168.1.10",
            "ssh_password": "hunter2",
            "ca_passphrase": "correct-horse",
            "api_token": "tok-abc",
            "basic_auth": "user:pass",
            "signing_key": "sign-material",
            "password_auth_enabled": 1,
            "nested": {"client_secret": "x", "ok": 1},
            "detail_json": FAKE_PEM,
            "ca_cert_pem": FAKE_CERT,
        }
        out = redact_value(raw)
        self.assertEqual(out["host"], "192.168.1.10")
        self.assertEqual(out["ssh_password"], REDACTED)
        self.assertEqual(out["ca_passphrase"], REDACTED)
        self.assertEqual(out["api_token"], REDACTED)
        self.assertEqual(out["basic_auth"], REDACTED)
        self.assertEqual(out["signing_key"], REDACTED)
        self.assertEqual(out["password_auth_enabled"], 1)
        self.assertEqual(out["nested"]["client_secret"], REDACTED)
        self.assertEqual(out["nested"]["ok"], 1)
        self.assertNotIn("BEGIN PRIVATE KEY", out["detail_json"])
        # Public cert kept for TLS debugging
        self.assertIn("BEGIN CERTIFICATE", out["ca_cert_pem"])

    def test_settings_public_rejects_arbitrary_objects(self) -> None:
        with self.assertRaises(TypeError):
            settings_public(object())


class SupportBundleExportTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        self.db = self.root / "registry.sqlite"
        self.registry = Registry(str(self.db))
        self.registry.upsert_gateway(
            id="gw1",
            host="192.168.1.50",
            ssh_user="pi",
            install_root="/opt/iot-gateway",
            fingerprint="fp-test",
            monitoring_ip="192.168.1.20",
            password_auth_enabled=1,
        )
        self.registry.upsert_device(
            gateway_id="gw1",
            id="sensor9",
            ip="10.0.0.9",
            topics_rw=["sensors/sensor9/#"],
            topics_r=["alerts/+"],
            cert_fingerprint="ab" * 32,
        )
        self.registry.audit(
            "register_device",
            gateway_id="gw1",
            device_id="sensor9",
            detail={
                "password": "should-not-leak",
                "pem": FAKE_PEM,
                "note": "ok",
            },
            actor="test",
        )
        self.settings = Settings(
            host="127.0.0.1",
            port=9137,
            data_dir=self.root,
            registry_path=self.db,
            api_token="live-api-token",
            ssh_password="ssh-secret",
            ca_passphrase="ca-secret",
            ssh_key_path="/home/op/.ssh/id_ed25519",
        )
        self.known_secrets = (
            "live-api-token",
            "ssh-secret",
            "ca-secret",
            "should-not-leak",
            "hunter2",
            "super-secret",
            "MATERIAL",
        )

    def test_settings_public_redacts_secrets(self) -> None:
        pub = settings_public(self.settings)
        self.assertEqual(pub["api_token"], REDACTED)
        self.assertEqual(pub["ssh_password"], REDACTED)
        self.assertEqual(pub["ca_passphrase"], REDACTED)
        self.assertEqual(pub["host"], "127.0.0.1")
        self.assertIn("id_ed25519", str(pub["ssh_key_path"]))

    def test_collect_payload_redacts_audit_and_keeps_password_auth_flag(self) -> None:
        payload = collect_bundle_payload(
            settings=self.settings,
            registry=self.registry,
            gateway_status={"gw1": {"agent": "up", "token": "x"}},
            control_logs=(
                f"signed with {FAKE_PEM}\n"
                "Bearer abcdef\n"
                "export IOTGW_CA_PASSPHRASE=super-secret\n"
                "password=hunter2\n"
                f"ca={FAKE_CERT}\n"
            ),
        )
        self.assertEqual(payload["settings"]["api_token"], REDACTED)
        self.assertEqual(payload["gateway_status"]["gw1"]["token"], REDACTED)
        gws = payload["gateways"]
        self.assertTrue(gws)
        self.assertEqual(gws[0]["password_auth_enabled"], 1)

        detail = payload["audit_log"][0].get("detail_json") or ""
        self.assertNotIn("BEGIN PRIVATE KEY", str(detail))
        self.assertNotIn("should-not-leak", str(detail))
        logs = payload["control_logs"]
        self.assertNotIn("BEGIN PRIVATE KEY", logs)
        self.assertNotIn("abcdef", logs)
        self.assertNotIn("super-secret", logs)
        self.assertNotIn("hunter2", logs)
        self.assertIn("BEGIN CERTIFICATE", logs)

    def test_write_zip_has_no_forbidden_markers_or_known_secrets(self) -> None:
        out = write_support_bundle(
            self.root / "bundle.zip",
            settings=self.settings,
            registry=self.registry,
            gateway_status={"ok": True},
            control_logs=(
                FAKE_PEM
                + "\npassword=hunter2\n"
                + "export IOTGW_CA_PASSPHRASE=super-secret\n"
                + FAKE_CERT
                + "\n"
            ),
            extra={
                "signing_private_key": "MATERIAL",
                "signing_key": "also-secret",
                "basic_auth": "u:p",
                "version": "0.1",
            },
        )
        self.assertTrue(out.is_file())
        hits = bundle_contains_forbidden(
            out, forbidden_substrings=list(self.known_secrets) + ["also-secret", "u:p"]
        )
        self.assertEqual(hits, [], msg=f"secrets leaked in bundle: {hits}")
        pem_hits = bundle_contains_forbidden(out)
        self.assertEqual(pem_hits, [], msg=f"private PEM in bundle: {pem_hits}")

        with zipfile.ZipFile(out) as zf:
            names = set(zf.namelist())
            self.assertIn("settings.json", names)
            self.assertIn("audit_log.json", names)
            self.assertIn("control.log", names)
            settings = json.loads(zf.read("settings.json"))
            self.assertEqual(settings["ssh_password"], REDACTED)
            self.assertEqual(settings["ca_passphrase"], REDACTED)
            extra = json.loads(zf.read("extra.json"))
            self.assertEqual(extra["signing_private_key"], REDACTED)
            self.assertEqual(extra["signing_key"], REDACTED)
            self.assertEqual(extra["basic_auth"], REDACTED)
            self.assertEqual(extra["version"], "0.1")
            control = zf.read("control.log").decode("utf-8")
            self.assertNotIn("BEGIN PRIVATE KEY", control)
            self.assertNotIn("hunter2", control)
            self.assertNotIn("super-secret", control)
            self.assertIn("BEGIN CERTIFICATE", control)
            registry = json.loads(zf.read("registry.json"))
            self.assertEqual(registry["gateways"][0]["password_auth_enabled"], 1)


if __name__ == "__main__":
    unittest.main()
