"""Unit tests for Grafana TLS certs and base config render helpers."""

from __future__ import annotations

import ipaddress
import os
import stat
import tempfile
import unittest
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes

from telemetry.grafana_certs import (
    ensure_grafana_admin_password,
    ensure_grafana_certs,
)
from telemetry.grafana_config import (
    render_datasources_yaml,
    render_grafana_ini,
    write_grafana_base_config,
)


class EnsureGrafanaCertsTests(unittest.TestCase):
    def test_creates_cert_and_key(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            certs = Path(tmp) / "certs"
            meta = ensure_grafana_certs(certs)
            self.assertTrue(meta["created"])
            self.assertTrue(meta["cert_file"].is_file())
            self.assertTrue(meta["key_file"].is_file())
            self.assertEqual(len(meta["fingerprint_sha256"]), 64)
            self.assertIsNotNone(meta["not_after"])

    def test_idempotent_without_force(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            certs = Path(tmp) / "certs"
            first = ensure_grafana_certs(certs)
            second = ensure_grafana_certs(certs)
            self.assertFalse(second["created"])
            self.assertEqual(
                first["fingerprint_sha256"], second["fingerprint_sha256"]
            )
            self.assertEqual(
                first["cert_file"].read_bytes(), second["cert_file"].read_bytes()
            )

    def test_force_regenerates(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            certs = Path(tmp) / "certs"
            first = ensure_grafana_certs(certs)
            second = ensure_grafana_certs(certs, force=True)
            self.assertTrue(second["created"])
            self.assertNotEqual(
                first["fingerprint_sha256"], second["fingerprint_sha256"]
            )

    def test_san_dns_localhost_and_loopback_ip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            certs = Path(tmp) / "certs"
            meta = ensure_grafana_certs(certs)
            cert = x509.load_pem_x509_certificate(meta["cert_file"].read_bytes())
            self.assertEqual(
                cert.subject.get_attributes_for_oid(
                    x509.oid.NameOID.COMMON_NAME
                )[0].value,
                "localhost",
            )
            san = cert.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            ).value
            self.assertIn(x509.DNSName("localhost"), list(san))
            self.assertIn(
                x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")), list(san)
            )
            # SHA-256 signature algorithm
            self.assertEqual(cert.signature_hash_algorithm.name, "sha256")
            # Matches returned fingerprint
            self.assertEqual(
                cert.fingerprint(hashes.SHA256()).hex(),
                meta["fingerprint_sha256"],
            )

    @unittest.skipUnless(os.name != "nt", "POSIX key mode only")
    def test_key_mode_600_on_posix(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            certs = Path(tmp) / "certs"
            meta = ensure_grafana_certs(certs)
            mode = meta["key_file"].stat().st_mode & 0o777
            self.assertEqual(mode, 0o600)


class EnsureGrafanaAdminPasswordTests(unittest.TestCase):
    def test_creates_once_and_reuses(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            certs = Path(tmp) / "certs"
            first = ensure_grafana_admin_password(certs)
            self.assertGreaterEqual(len(first), 24)
            path = certs / "grafana-admin.pass"
            self.assertTrue(path.is_file())
            second = ensure_grafana_admin_password(certs)
            self.assertEqual(first, second)
            self.assertEqual(path.read_text(encoding="utf-8").strip(), first)

    @unittest.skipUnless(os.name != "nt", "POSIX password file mode only")
    def test_password_mode_600_on_posix(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            certs = Path(tmp) / "certs"
            ensure_grafana_admin_password(certs)
            mode = (certs / "grafana-admin.pass").stat().st_mode & 0o777
            self.assertEqual(mode, 0o600)
            self.assertFalse(bool(mode & (stat.S_IRWXG | stat.S_IRWXO)))


class RenderGrafanaConfigTests(unittest.TestCase):
    def test_render_grafana_ini_https_localhost(self) -> None:
        ini = render_grafana_ini(
            grafana_data=Path("/data/grafana-data"),
            logs_dir=Path("/data/logs"),
            plugins_dir=Path("/data/grafana-data/plugins"),
            provisioning_dir=Path("/data/config/provisioning"),
            cert_file=Path("/data/certs/grafana.crt"),
            cert_key=Path("/data/certs/grafana.key"),
            admin_password="test-pass-value",
            http_port=9140,
        )
        self.assertIn("protocol = https", ini)
        self.assertIn("http_addr = 127.0.0.1", ini)
        self.assertIn("http_port = 9140", ini)
        self.assertIn("root_url = https://127.0.0.1:9140/", ini)
        self.assertIn("cert_file = /data/certs/grafana.crt", ini)
        self.assertIn("cert_key = /data/certs/grafana.key", ini)
        self.assertIn("admin_password = test-pass-value", ini)
        self.assertIn("[auth.anonymous]", ini)
        self.assertIn("org_role = Admin", ini)
        self.assertIn("enabled = true", ini)
        self.assertIn("[auth.basic]", ini)
        self.assertIn("enabled = false", ini)
        self.assertIn("cookie_secure = true", ini)
        self.assertIn("cookie_samesite = strict", ini)
        self.assertIn('min_tls_version = "TLS1.2"', ini)
        self.assertNotIn("allow_loading_unsigned_plugins", ini)

    def test_render_datasources_prom_loki_only(self) -> None:
        yaml = render_datasources_yaml()
        self.assertIn("uid: iotgw-prometheus", yaml)
        self.assertIn("uid: iotgw-loki", yaml)
        self.assertIn("http://127.0.0.1:9090", yaml)
        self.assertIn("http://127.0.0.1:3100", yaml)
        self.assertNotIn("kafka", yaml.lower())
        self.assertIn("isDefault: true", yaml)

    def test_write_grafana_base_config(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            paths = write_grafana_base_config(
                root / "config",
                grafana_data=root / "grafana-data",
                logs_dir=root / "logs",
                plugins_dir=root / "grafana-data" / "plugins",
                cert_file=root / "certs" / "grafana.crt",
                cert_key=root / "certs" / "grafana.key",
                admin_password="pw",
            )
            self.assertTrue(paths["grafana_ini"].is_file())
            self.assertTrue(paths["datasources_yaml"].is_file())
            text = paths["grafana_ini"].read_text(encoding="utf-8")
            self.assertIn("protocol = https", text)
            ds = paths["datasources_yaml"].read_text(encoding="utf-8")
            self.assertIn("iotgw-prometheus", ds)
            self.assertIn("iotgw-loki", ds)


if __name__ == "__main__":
    unittest.main()
