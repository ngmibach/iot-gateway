"""Unit tests for Grafana TLS certs and base config render helpers."""

from __future__ import annotations

import ipaddress
import os
import re
import stat
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from telemetry.grafana_certs import (
    ensure_grafana_admin_password,
    ensure_grafana_certs,
)
from telemetry.grafana_config import (
    render_datasources_yaml,
    render_grafana_ini,
    sync_grafana_datasources,
    write_grafana_base_config,
)


def _ini_section(ini: str, name: str) -> str:
    """Return body text for ``[name]`` up to the next section header."""
    match = re.search(
        rf"^\[{re.escape(name)}\]\s*\n(.*?)(?=^\[|\Z)",
        ini,
        flags=re.MULTILINE | re.DOTALL,
    )
    if match is None:
        raise AssertionError(f"missing INI section [{name}]")
    return match.group(1)


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
            before = datetime.now(timezone.utc)
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
            self.assertEqual(cert.signature_hash_algorithm.name, "sha256")
            self.assertEqual(
                cert.fingerprint(hashes.SHA256()).hex(),
                meta["fingerprint_sha256"],
            )
            bc = cert.extensions.get_extension_for_class(
                x509.BasicConstraints
            ).value
            self.assertTrue(bc.ca)
            self.assertEqual(bc.path_length, 0)
            eku = cert.extensions.get_extension_for_class(
                x509.ExtendedKeyUsage
            ).value
            self.assertIn(x509.oid.ExtendedKeyUsageOID.SERVER_AUTH, list(eku))
            key = load_pem_private_key(meta["key_file"].read_bytes(), password=None)
            self.assertIsInstance(key, rsa.RSAPrivateKey)
            self.assertEqual(key.key_size, 2048)
            # Default validity_days=825 (± a few minutes of clock skew / not_before offset).
            expected = before + timedelta(days=825)
            delta = abs(meta["not_after"] - expected)
            self.assertLess(delta, timedelta(minutes=5))

    def test_validity_days_shortens_not_after(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            certs = Path(tmp) / "certs"
            before = datetime.now(timezone.utc)
            meta = ensure_grafana_certs(certs, validity_days=30)
            expected = before + timedelta(days=30)
            delta = abs(meta["not_after"] - expected)
            self.assertLess(delta, timedelta(minutes=5))

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
        anonymous = _ini_section(ini, "auth.anonymous")
        self.assertRegex(anonymous, r"(?m)^enabled = true\s*$")
        self.assertRegex(anonymous, r"(?m)^org_role = Admin\s*$")
        basic = _ini_section(ini, "auth.basic")
        self.assertRegex(basic, r"(?m)^enabled = false\s*$")
        self.assertIn("cookie_secure = true", ini)
        self.assertIn("cookie_samesite = strict", ini)
        self.assertIn('min_tls_version = "TLS1.2"', ini)
        self.assertIn("# Generated by native telemetry", ini)
        plugins = _ini_section(ini, "plugins")
        self.assertIn(
            "allow_loading_unsigned_plugins = hamedkarbasi93-kafka-datasource",
            plugins,
        )

    def test_render_datasources_prom_loki_only(self) -> None:
        yaml = render_datasources_yaml()
        self.assertIn("uid: iotgw-prometheus", yaml)
        self.assertIn("uid: iotgw-loki", yaml)
        self.assertIn("http://127.0.0.1:9090", yaml)
        self.assertIn("http://127.0.0.1:3100", yaml)
        self.assertNotIn("kafka", yaml.lower())
        self.assertIn("isDefault: true", yaml)

    def test_render_datasources_with_gateways(self) -> None:
        import hashlib

        yaml = render_datasources_yaml(
            gateways=[
                {"id": "gw-1", "host": "192.168.1.50"},
                {"gateway_id": "bad_chars!", "host": "10.0.0.2"},
                {"id": "no-host", "host": ""},
            ]
        )
        self.assertIn("uid: iotgw-prometheus", yaml)
        self.assertIn("uid: iotgw-loki", yaml)
        self.assertIn("uid: iotgw-kafka-gw-1", yaml)
        self.assertIn('bootstrapServers: "192.168.1.50:9092"', yaml)
        self.assertIn("type: hamedkarbasi93-kafka-datasource", yaml)
        self.assertIn('name: "Kafka (gw-1)"', yaml)
        suffix = hashlib.sha256(b"bad_chars!").hexdigest()[:8]
        self.assertIn(f"uid: iotgw-kafka-bad-chars-{suffix}", yaml)
        self.assertIn('bootstrapServers: "10.0.0.2:9092"', yaml)
        self.assertNotIn("iotgw-kafka-no-host", yaml)
        self.assertIn('securityProtocol: "PLAINTEXT"', yaml)

    def test_render_datasources_rejects_yaml_injection(self) -> None:
        import hashlib

        yaml = render_datasources_yaml(
            gateways=[
                {
                    "id": 'gw"\n    injected: true\n  - name: Evil',
                    "host": '1.2.3.4"\n    url: http://evil',
                },
                {"id": "ok", "host": "not a host!!"},
                {"id": "gw_1", "host": "10.0.0.1"},
                {"id": "gw!1", "host": "10.0.0.2"},
            ]
        )
        self.assertNotIn("injected:", yaml)
        self.assertNotIn("http://evil", yaml)
        self.assertNotIn("not a host", yaml)
        # Distinct ids that sanitize alike must not share a uid.
        u1 = "iotgw-kafka-gw-1-" + hashlib.sha256(b"gw_1").hexdigest()[:8]
        u2 = "iotgw-kafka-gw-1-" + hashlib.sha256(b"gw!1").hexdigest()[:8]
        self.assertNotEqual(u1, u2)
        self.assertIn(f"uid: {u1}", yaml)
        self.assertIn(f"uid: {u2}", yaml)
        self.assertNotIn("uid: iotgw-kafka-gw-1\n", yaml)
        self.assertIn('bootstrapServers: "10.0.0.1:9092"', yaml)
        self.assertIn('bootstrapServers: "10.0.0.2:9092"', yaml)
        # Injected sibling keys / breakout hosts must not appear.
        self.assertNotIn("url: http://evil", yaml)
        self.assertNotIn("name: Evil", yaml)

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
                gateways=[{"id": "gateway", "host": "172.20.10.2"}],
            )
            self.assertTrue(paths["grafana_ini"].is_file())
            self.assertTrue(paths["datasources_yaml"].is_file())
            text = paths["grafana_ini"].read_text(encoding="utf-8")
            self.assertIn("protocol = https", text)
            self.assertIn(
                "allow_loading_unsigned_plugins = hamedkarbasi93-kafka-datasource",
                text,
            )
            ds = paths["datasources_yaml"].read_text(encoding="utf-8")
            self.assertIn("iotgw-prometheus", ds)
            self.assertIn("iotgw-loki", ds)
            self.assertIn("iotgw-kafka-gateway", ds)
            self.assertIn("172.20.10.2:9092", ds)


class SyncGrafanaDatasourcesTests(unittest.TestCase):
    def test_sync_writes_file_reload_mocked(self) -> None:
        from registry.registry import Registry

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            reg_path = root / "registry.sqlite"
            reg = Registry(str(reg_path))
            try:
                reg.upsert_gateway(
                    "gateway",
                    host="192.168.1.50",
                    ssh_user="ubuntu",
                    install_root="/opt/iot-gateway-agent",
                    fingerprint="SHA256:x",
                )
            finally:
                reg.close()

            config_dir = root / "telemetry" / "config"
            with mock.patch(
                "telemetry.grafana_config._grafana_https_healthy",
                return_value=True,
            ):
                with mock.patch(
                    "telemetry.grafana_config._reload_grafana_datasources",
                    return_value=True,
                ) as reload_mock:
                    result = sync_grafana_datasources(
                        config_dir=config_dir,
                        registry_path=reg_path,
                        reload=True,
                    )
                    reload_mock.assert_called_once()

            self.assertEqual(result["gateways"], 1)
            self.assertTrue(result["reloaded"])
            ds_path = Path(result["path"])
            self.assertTrue(ds_path.is_file())
            text = ds_path.read_text(encoding="utf-8")
            self.assertIn("iotgw-kafka-gateway", text)
            self.assertIn("192.168.1.50:9092", text)

    def test_sync_skips_reload_when_grafana_down(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config_dir = root / "config"
            with mock.patch(
                "telemetry.grafana_config._grafana_https_healthy",
                return_value=False,
            ):
                with mock.patch(
                    "telemetry.grafana_config._reload_grafana_datasources"
                ) as reload_mock:
                    result = sync_grafana_datasources(
                        config_dir=config_dir,
                        registry_path=root / "missing.sqlite",
                        reload=True,
                    )
                    reload_mock.assert_not_called()
            self.assertEqual(result["gateways"], 0)
            self.assertFalse(result["reloaded"])
            self.assertTrue(Path(result["path"]).is_file())

    def test_sync_rejects_non_allowlisted_grafana_url(self) -> None:
        from telemetry.grafana_config import (
            _grafana_https_healthy,
            _reload_grafana_datasources,
        )

        self.assertFalse(_grafana_https_healthy("https://evil.example:9140"))
        self.assertFalse(_reload_grafana_datasources("http://127.0.0.1:9140"))
        with mock.patch("telemetry.grafana_config._grafana_opener") as opener:
            self.assertFalse(
                _grafana_https_healthy("https://evil.example/steal")
            )
            opener.assert_not_called()


if __name__ == "__main__":
    unittest.main()
