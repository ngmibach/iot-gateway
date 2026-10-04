"""Tests for CSR generation and bundle assembly."""

from __future__ import annotations

import unittest
import zipfile
from io import BytesIO
from unittest.mock import MagicMock

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from actions.csr import (
    assemble_cert_bundle,
    generate_client_key_and_csr,
    sign_csr_on_gateway,
)
from actions.paths import GatewayPaths
from actions.ssh import CommandResult
from tests.cert_helpers import local_self_sign_for_tests


class TestCsr(unittest.TestCase):
    def test_generate_and_self_sign(self) -> None:
        mat = generate_client_key_and_csr("sensor9")
        self.assertIn(b"BEGIN RSA PRIVATE KEY", mat.private_key_pem)
        self.assertIn(b"BEGIN CERTIFICATE REQUEST", mat.csr_pem)
        csr = x509.load_pem_x509_csr(mat.csr_pem)
        self.assertEqual(
            csr.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value,
            "sensor9",
        )
        signed = local_self_sign_for_tests(mat)
        self.assertIn(b"BEGIN CERTIFICATE", signed.client_crt_pem)
        self.assertIsNotNone(signed.fingerprint_sha256)

    def test_assemble_bundle(self) -> None:
        mat = generate_client_key_and_csr("sensor9")
        signed = local_self_sign_for_tests(mat)
        blob = assemble_cert_bundle(
            ca_crt_pem=signed.ca_crt_pem,
            client_crt_pem=signed.client_crt_pem,
            client_key_pem=mat.private_key_pem,
        )
        with zipfile.ZipFile(BytesIO(blob)) as zf:
            names = set(zf.namelist())
            self.assertEqual(names, {"ca.crt", "client.crt", "client.key"})
            key = zf.read("client.key")
            serialization.load_pem_private_key(key, password=None)

    def test_sign_csr_on_gateway_uses_passin_file(self) -> None:
        mat = generate_client_key_and_csr("sensor9")
        signed_local = local_self_sign_for_tests(mat)
        ssh = MagicMock()
        written: dict[str, bytes] = {}

        def write_bytes(path: str, data: bytes, *, mode: int = 0o600) -> None:
            written[path] = data

        def read_bytes(path: str) -> bytes:
            if path.endswith(".crt") and "iotgw-crt-" in path:
                return signed_local.client_crt_pem
            if path.endswith("ca.crt"):
                return signed_local.ca_crt_pem
            raise FileNotFoundError(path)

        runs: list[str] = []

        def run(cmd: str, *, timeout: float | None = None) -> CommandResult:
            runs.append(cmd)
            return CommandResult(argv=cmd, exit_code=0, stdout="", stderr="")

        unlinked: list[str] = []
        ssh.write_bytes.side_effect = write_bytes
        ssh.read_bytes.side_effect = read_bytes
        ssh.run.side_effect = run
        ssh.unlink.side_effect = lambda p: unlinked.append(p)

        paths = GatewayPaths("/opt/iot-gateway")
        result = sign_csr_on_gateway(
            ssh,
            paths,
            mat.csr_pem,
            ca_passphrase="not-admin",
            days=30,
        )
        self.assertEqual(result.client_crt_pem, signed_local.client_crt_pem)
        self.assertTrue(any("-passin file:/tmp/iotgw-ca-pass-" in c for c in runs))
        self.assertFalse(any("passin pass:" in c for c in runs))
        pass_files = [p for p in written if "iotgw-ca-pass-" in p]
        self.assertEqual(len(pass_files), 1)
        self.assertEqual(written[pass_files[0]], b"not-admin")
        self.assertTrue(any("iotgw-ca-pass-" in p for p in unlinked))
        self.assertTrue(any("iotgw-csr-" in p for p in unlinked))

    def test_rejects_admin_passphrase(self) -> None:
        mat = generate_client_key_and_csr("sensor9")
        ssh = MagicMock()
        with self.assertRaises(ValueError):
            sign_csr_on_gateway(
                ssh,
                GatewayPaths(),
                mat.csr_pem,
                ca_passphrase="admin",
            )


if __name__ == "__main__":
    unittest.main()
