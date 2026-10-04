"""Operator-side client key/CSR + gateway CA sign via ``-passin file:``."""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING, Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

if TYPE_CHECKING:
    from .ssh import SSHClient

from .paths import GatewayPaths
from .shellutil import shell_quote


@dataclass
class ClientKeyMaterial:
    private_key_pem: bytes
    csr_pem: bytes
    cn: str


@dataclass
class SignedClientCert:
    client_crt_pem: bytes
    ca_crt_pem: bytes
    not_valid_after: Optional[datetime] = None
    fingerprint_sha256: Optional[str] = None


def generate_client_key_and_csr(
    cn: str,
    *,
    country: str = "VN",
    state: str = "Hanoi",
    city: str = "Hanoi",
    organization: str = "My IOT Org",
    org_unit: str = "Sensors",
    key_size: int = 2048,
) -> ClientKeyMaterial:
    """Generate RSA key + CSR in memory (client key never touches the gateway)."""
    if not cn:
        raise ValueError("CN required")
    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, country),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state),
            x509.NameAttribute(NameOID.LOCALITY_NAME, city),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, org_unit),
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
        ]
    )
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(subject)
        .sign(key, hashes.SHA256())
    )
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    csr_pem = csr.public_bytes(serialization.Encoding.PEM)
    return ClientKeyMaterial(private_key_pem=key_pem, csr_pem=csr_pem, cn=cn)


def _cert_meta(pem: bytes) -> tuple[Optional[datetime], Optional[str]]:
    try:
        cert = x509.load_pem_x509_certificate(pem)
        fp = cert.fingerprint(hashes.SHA256()).hex()
        return cert.not_valid_after_utc, fp
    except Exception:
        return None, None


def sign_csr_on_gateway(
    ssh: "SSHClient",
    paths: GatewayPaths,
    csr_pem: bytes,
    ca_passphrase: str,
    *,
    days: int = 730,
    reject_default_admin_passphrase: bool = True,
) -> SignedClientCert:
    """SFTP CSR + passin file (0600), openssl sign on gateway, unlink temps.

    Never uses ``-passin pass:`` on remote argv.
    """
    if reject_default_admin_passphrase and ca_passphrase == "admin":
        raise ValueError("production profile refuses CA passphrase 'admin'")
    if not ca_passphrase:
        raise ValueError("CA passphrase required")

    token = secrets.token_hex(8)
    remote_csr = f"/tmp/iotgw-csr-{token}.csr"
    remote_crt = f"/tmp/iotgw-crt-{token}.crt"
    remote_pass = f"/tmp/iotgw-ca-pass-{token}"

    try:
        ssh.write_bytes(remote_csr, csr_pem, mode=0o600)
        ssh.write_bytes(remote_pass, ca_passphrase.encode("utf-8"), mode=0o600)

        # passin file: path is unquoted; token paths have no spaces/metachars.
        cmd = (
            "openssl x509 -req"
            f" -in {shell_quote(remote_csr)}"
            f" -CA {shell_quote(paths.ca_crt)}"
            f" -CAkey {shell_quote(paths.ca_key)}"
            f" -passin file:{remote_pass}"
            " -CAcreateserial"
            f" -out {shell_quote(remote_crt)}"
            f" -days {int(days)}"
        )
        ssh.run(cmd, timeout=300).check()

        client_crt = ssh.read_bytes(remote_crt)
        ca_crt = ssh.read_bytes(paths.ca_crt)
        not_after, fp = _cert_meta(client_crt)
        return SignedClientCert(
            client_crt_pem=client_crt,
            ca_crt_pem=ca_crt,
            not_valid_after=not_after,
            fingerprint_sha256=fp,
        )
    finally:
        for path in (remote_csr, remote_crt, remote_pass):
            try:
                ssh.unlink(path)
            except Exception:
                pass


def assemble_cert_bundle(
    *,
    ca_crt_pem: bytes,
    client_crt_pem: bytes,
    client_key_pem: bytes,
) -> bytes:
    """Build an in-memory zip of the three PEM files."""
    import io
    import zipfile

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("ca.crt", ca_crt_pem)
        zf.writestr("client.crt", client_crt_pem)
        zf.writestr("client.key", client_key_pem)
    return buf.getvalue()
