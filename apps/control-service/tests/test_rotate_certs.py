"""Unit tests for server vs CA certificate rotation (K7 / K15)."""

from __future__ import annotations

import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from actions.csr import generate_client_key_and_csr, sign_csr_on_gateway
from actions.paths import GatewayPaths
from actions.ssh import CommandResult
from certs.rotate import (
    rotate_ca,
    rotate_server_cert,
    server_san_extfile,
)
from registry.registry import Registry
from tests.cert_helpers import local_self_sign_for_tests
from tests.fake_ssh import FakeSSH

ROOT = "/opt/iot-gateway"
GATEWAY_IP = "192.168.40.177"


def _rsa_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _pem_key(key: rsa.RSAPrivateKey, *, encrypted: bool = False) -> bytes:
    if encrypted:
        enc = serialization.BestAvailableEncryption(b"not-admin")
    else:
        enc = serialization.NoEncryption()
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=enc,
    )


def _self_signed_ca(key: rsa.RSAPrivateKey, cn: str = "My IOT CA Root") -> bytes:
    now = datetime.now(timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=3650))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM)


def _sign_csr_pem(
    csr_pem: bytes,
    ca_key: rsa.RSAPrivateKey,
    ca_crt_pem: bytes,
    *,
    days: int = 30,
    san_ip: str | None = None,
) -> bytes:
    csr = x509.load_pem_x509_csr(csr_pem)
    ca_crt = x509.load_pem_x509_certificate(ca_crt_pem)
    now = datetime.now(timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(ca_crt.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=days))
    )
    if san_ip is not None:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ipaddress_ip(san_ip))]),
            critical=False,
        )
    cert = builder.sign(ca_key, hashes.SHA256())
    return cert.public_bytes(serialization.Encoding.PEM)


def ipaddress_ip(value: str):
    import ipaddress

    return ipaddress.ip_address(value)


def _base_files(ca_key: rsa.RSAPrivateKey, ca_crt: bytes) -> dict[str, str]:
    server_key = _rsa_key()
    return {
        f"{ROOT}/certs/ca.crt": ca_crt.decode(),
        f"{ROOT}/certs/ca.key": _pem_key(ca_key, encrypted=True).decode(),
        f"{ROOT}/certs/server.crt": "-----BEGIN CERTIFICATE-----\nOLD\n-----END CERTIFICATE-----\n",
        f"{ROOT}/certs/server.key": _pem_key(server_key).decode(),
        f"{ROOT}/certs/server.pem": "old-pem",
    }


def _openssl_handler(
    ssh: FakeSSH,
    *,
    ca_key: rsa.RSAPrivateKey,
    ca_crt_pem: bytes,
    gateway_ip: str = GATEWAY_IP,
):
    """Simulate gateway openssl: genrsa / req -x509 / x509 -req (+ SAN)."""

    def run_handler(cmd: str) -> CommandResult:
        parts = cmd.split()
        if "openssl genrsa" in cmd:
            out = parts[parts.index("-out") + 1].strip("'")
            # New CA key path during rotate_ca, or ignored for server (key on operator).
            enc = " -aes256" in cmd or "-aes256" in parts
            ssh.files[out] = _pem_key(_rsa_key(), encrypted=enc)
            return CommandResult(argv=cmd, exit_code=0, stdout="", stderr="")

        if "openssl req" in cmd and "-x509" in parts:
            out = parts[parts.index("-out") + 1].strip("'")
            # Fresh CA cert for rotate_ca.
            new_key = _rsa_key()
            # Prefer key written by preceding genrsa when present.
            key_path = parts[parts.index("-key") + 1].strip("'")
            key_pem = ssh.files.get(key_path)
            if key_pem:
                try:
                    loaded = serialization.load_pem_private_key(
                        key_pem, password=b"not-admin"
                    )
                    assert isinstance(loaded, rsa.RSAPrivateKey)
                    new_key = loaded
                except Exception:
                    loaded = serialization.load_pem_private_key(key_pem, password=None)
                    assert isinstance(loaded, rsa.RSAPrivateKey)
                    new_key = loaded
            ssh.files[out] = _self_signed_ca(new_key)
            # Keep handler ca_crt in sync when installing via rotate later.
            return CommandResult(argv=cmd, exit_code=0, stdout="", stderr="")

        if "openssl x509 -req" in cmd:
            out = parts[parts.index("-out") + 1].strip("'")
            in_path = parts[parts.index("-in") + 1].strip("'")
            csr_pem = ssh.files[in_path]
            san_ip = None
            if "-extfile" in parts:
                ext_path = parts[parts.index("-extfile") + 1].strip("'")
                ext = ssh.files[ext_path].decode()
                # Must match cert-generation.sh, not SAN-less update_key.yaml.
                assert "subjectAltName=IP:" in ext, ext
                san_ip = ext.strip().split("IP:", 1)[1].strip()
            # After rotate_ca, CA files on disk may have been replaced.
            ca_pem = ssh.files.get(f"{ROOT}/certs/ca.crt", ca_crt_pem)
            if isinstance(ca_pem, str):
                ca_pem = ca_pem.encode()
            try:
                active_key = serialization.load_pem_private_key(
                    ssh.files[f"{ROOT}/certs/ca.key"],
                    password=b"not-admin",
                )
                assert isinstance(active_key, rsa.RSAPrivateKey)
            except Exception:
                active_key = ca_key
            ssh.files[out] = _sign_csr_pem(
                csr_pem if isinstance(csr_pem, bytes) else csr_pem.encode(),
                active_key,
                ca_pem if isinstance(ca_pem, bytes) else ca_pem.encode(),
                san_ip=san_ip,
            )
            return CommandResult(argv=cmd, exit_code=0, stdout="", stderr="")

        return CommandResult(argv=cmd, exit_code=0, stdout="", stderr="")

    return run_handler


class TestServerSanExtfile(unittest.TestCase):
    def test_matches_cert_generation_sh(self) -> None:
        self.assertEqual(
            server_san_extfile(GATEWAY_IP),
            f"subjectAltName=IP:{GATEWAY_IP}\n",
        )


class TestRotateServerCert(unittest.TestCase):
    def setUp(self) -> None:
        self.ca_key = _rsa_key()
        self.ca_crt = _self_signed_ca(self.ca_key)

    def test_rotate_server_uses_ip_san_and_passin_file(self) -> None:
        ssh = FakeSSH(_base_files(self.ca_key, self.ca_crt))
        ssh._run_handler = _openssl_handler(
            ssh, ca_key=self.ca_key, ca_crt_pem=self.ca_crt
        )
        mat = generate_client_key_and_csr(cn=GATEWAY_IP, org_unit="Broker")
        result = rotate_server_cert(
            ssh,  # type: ignore[arg-type]
            gateway_ip=GATEWAY_IP,
            ca_passphrase="not-admin",
            key_material=mat,
        )
        self.assertTrue(result.ok)
        self.assertEqual(result.status, "ok")
        self.assertEqual(result.details.get("san"), f"IP:{GATEWAY_IP}")

        runs = ssh.commands
        self.assertTrue(any("-passin file:/tmp/iotgw-ca-pass-" in c for c in runs))
        self.assertFalse(any("passin pass:" in c for c in runs))
        self.assertFalse(any("passout pass:" in c for c in runs))
        self.assertTrue(any("-extfile" in c for c in runs))
        self.assertTrue(any("iotgw-ext-" in p for p in ssh.unlinked))
        self.assertTrue(any("iotgw-ca-pass-" in p for p in ssh.unlinked))

        # Installed server cert carries IP SAN.
        installed = x509.load_pem_x509_certificate(
            ssh.read_bytes(f"{ROOT}/certs/server.crt")
        )
        san = installed.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        ips = san.value.get_values_for_type(x509.IPAddress)
        self.assertEqual([str(i) for i in ips], [GATEWAY_IP])

        pem = ssh.read_bytes(f"{ROOT}/certs/server.pem")
        self.assertIn(b"BEGIN CERTIFICATE", pem)
        self.assertIn(b"BEGIN RSA PRIVATE KEY", pem)
        self.assertTrue(any("restart mosquitto" in c for c in runs))
        self.assertTrue(any("docker kill -s HUP" in c for c in runs))
        self.assertTrue(
            any(k.startswith(f"{ROOT}/certs/server.crt.bak.") for k in ssh.files)
        )
        self.assertTrue(result.server_crt_pem)

    def test_rotate_server_rejects_admin_and_cidr(self) -> None:
        ssh = FakeSSH(_base_files(self.ca_key, self.ca_crt))
        bad_admin = rotate_server_cert(
            ssh,  # type: ignore[arg-type]
            gateway_ip=GATEWAY_IP,
            ca_passphrase="admin",
        )
        self.assertFalse(bad_admin.ok)
        self.assertIn("admin", bad_admin.message)

        bad_cidr = rotate_server_cert(
            ssh,  # type: ignore[arg-type]
            gateway_ip="10.0.0.0/24",
            ca_passphrase="not-admin",
        )
        self.assertFalse(bad_cidr.ok)
        self.assertIn("CIDR", bad_cidr.message)

    def test_sign_csr_extfile_passin_only(self) -> None:
        mat = generate_client_key_and_csr(cn=GATEWAY_IP, org_unit="Broker")
        ssh = FakeSSH(_base_files(self.ca_key, self.ca_crt))
        ssh._run_handler = _openssl_handler(
            ssh, ca_key=self.ca_key, ca_crt_pem=self.ca_crt
        )
        signed = sign_csr_on_gateway(
            ssh,  # type: ignore[arg-type]
            GatewayPaths(ROOT),
            mat.csr_pem,
            "not-admin",
            extfile_content=server_san_extfile(GATEWAY_IP),
        )
        cert = x509.load_pem_x509_certificate(signed.client_crt_pem)
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        self.assertEqual(
            [str(i) for i in san.value.get_values_for_type(x509.IPAddress)],
            [GATEWAY_IP],
        )
        self.assertTrue(any("-extfile" in c for c in ssh.commands))
        self.assertFalse(any("passin pass:" in c for c in ssh.commands))


class TestRotateCA(unittest.TestCase):
    def setUp(self) -> None:
        self.ca_key = _rsa_key()
        self.ca_crt = _self_signed_ca(self.ca_key)
        self._tmpdir = tempfile.TemporaryDirectory()
        self.registry = Registry(os.path.join(self._tmpdir.name, "registry.sqlite"))
        self.registry.upsert_gateway(
            "gw1",
            host=GATEWAY_IP,
            ssh_user="ubuntu",
            install_root=ROOT,
            fingerprint="abc",
        )
        self.registry.upsert_device("gw1", "sensor1", ip="10.0.0.1")
        self.registry.upsert_device("gw1", "sensor2", ip="10.0.0.2")

    def tearDown(self) -> None:
        self.registry.close()
        self._tmpdir.cleanup()

    def test_requires_break_glass_confirm(self) -> None:
        ssh = FakeSSH(_base_files(self.ca_key, self.ca_crt))
        result = rotate_ca(
            ssh,  # type: ignore[arg-type]
            gateway_ip=GATEWAY_IP,
            ca_passphrase="not-admin",
            confirm_break_glass=False,
            device_ids=["sensor1"],
        )
        self.assertFalse(result.ok)
        self.assertIn("break-glass", result.message)

    def test_rotate_ca_reissues_registry_devices(self) -> None:
        ssh = FakeSSH(_base_files(self.ca_key, self.ca_crt))
        ssh._run_handler = _openssl_handler(
            ssh, ca_key=self.ca_key, ca_crt_pem=self.ca_crt
        )
        mats = {
            "sensor1": generate_client_key_and_csr("sensor1"),
            "sensor2": generate_client_key_and_csr("sensor2"),
        }
        server_mat = generate_client_key_and_csr(cn=GATEWAY_IP, org_unit="Broker")
        result = rotate_ca(
            ssh,  # type: ignore[arg-type]
            gateway_ip=GATEWAY_IP,
            ca_passphrase="not-admin",
            confirm_break_glass=True,
            registry=self.registry,
            gateway_id="gw1",
            server_key_material=server_mat,
            device_key_material=mats,
        )
        self.assertTrue(result.ok, result.message)
        self.assertEqual(result.status, "ok")
        self.assertEqual({d.device_id for d in result.devices}, {"sensor1", "sensor2"})
        self.assertIsNotNone(result.ca_crt_pem)
        self.assertIsNotNone(result.server_crt_pem)

        runs = ssh.commands
        self.assertTrue(any("-passout file:/tmp/iotgw-ca-pass-" in c for c in runs))
        self.assertTrue(any("-passin file:/tmp/iotgw-ca-pass-" in c for c in runs))
        self.assertFalse(any("passout pass:" in c for c in runs))
        self.assertFalse(any("passin pass:" in c for c in runs))
        # Server step must keep IP SAN (not update_key.yaml SAN-less).
        self.assertTrue(any("-extfile" in c and "x509 -req" in c for c in runs))
        self.assertEqual(result.details.get("san"), f"IP:{GATEWAY_IP}")

        server_crt = x509.load_pem_x509_certificate(
            ssh.read_bytes(f"{ROOT}/certs/server.crt")
        )
        san = server_crt.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        self.assertEqual(
            [str(i) for i in san.value.get_values_for_type(x509.IPAddress)],
            [GATEWAY_IP],
        )

        for device_id in ("sensor1", "sensor2"):
            row = self.registry.get_device("gw1", device_id)
            assert row is not None
            self.assertIsNotNone(row["cert_fingerprint"])
            self.assertIsNotNone(row["cert_expires_at"])

        audit = self.registry.list_audit(gateway_id="gw1")
        actions = {a["action"] for a in audit}
        self.assertIn("rotate_ca", actions)
        self.assertIn("rotate_ca_reissue_device", actions)

        for item in result.devices:
            self.assertIn(b"BEGIN CERTIFICATE", item.client_crt_pem)
            self.assertIn(b"BEGIN RSA PRIVATE KEY", item.client_key_pem)
            self.assertTrue(item.cert_bundle)

    def test_rotate_ca_rejects_admin(self) -> None:
        ssh = FakeSSH(_base_files(self.ca_key, self.ca_crt))
        result = rotate_ca(
            ssh,  # type: ignore[arg-type]
            gateway_ip=GATEWAY_IP,
            ca_passphrase="admin",
            confirm_break_glass=True,
            device_ids=[],
        )
        self.assertFalse(result.ok)
        self.assertIn("admin", result.message)


class TestLocalSelfSignStillWorks(unittest.TestCase):
    def test_helper(self) -> None:
        mat = generate_client_key_and_csr("sensor9")
        signed = local_self_sign_for_tests(mat)
        self.assertIn(b"BEGIN CERTIFICATE", signed.client_crt_pem)


if __name__ == "__main__":
    unittest.main()
