"""Self-signed localhost TLS material for native Grafana HTTPS."""

from __future__ import annotations

import ipaddress
import os
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

_CERT_NAME = "grafana.crt"
_KEY_NAME = "grafana.key"
_ADMIN_PASS_NAME = "grafana-admin.pass"
_CN = "localhost"


def _chmod_private(path: Path) -> None:
    """POSIX: 0o600. Windows: best-effort chmod (no Unix ACL claim)."""
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def ensure_grafana_admin_password(certs_dir: Path) -> str:
    """Return admin password from ``grafana-admin.pass``, creating once if missing."""
    certs_dir = Path(certs_dir)
    certs_dir.mkdir(parents=True, exist_ok=True)
    path = certs_dir / _ADMIN_PASS_NAME
    if path.is_file():
        text = path.read_text(encoding="utf-8").strip()
        if text:
            return text
    password = secrets.token_urlsafe(24)
    path.write_text(password + "\n", encoding="utf-8")
    _chmod_private(path)
    return password


def _load_cert_meta(cert_path: Path, key_path: Path) -> dict[str, Any]:
    pem = cert_path.read_bytes()
    cert = x509.load_pem_x509_certificate(pem)
    return {
        "cert_file": cert_path,
        "key_file": key_path,
        "fingerprint_sha256": cert.fingerprint(hashes.SHA256()).hex(),
        "not_after": cert.not_valid_after_utc,
        "created": False,
    }


def ensure_grafana_certs(
    certs_dir: Path,
    *,
    force: bool = False,
    validity_days: int = 825,
) -> dict[str, Any]:
    """Create ``grafana.crt`` / ``grafana.key`` if missing (or ``force``).

    CN=localhost; SAN=DNS:localhost + IP:127.0.0.1; RSA-2048; SHA-256.
    On POSIX the key is ``chmod 0o600``. On Windows chmod is best-effort only.
    """
    certs_dir = Path(certs_dir)
    certs_dir.mkdir(parents=True, exist_ok=True)
    cert_path = certs_dir / _CERT_NAME
    key_path = certs_dir / _KEY_NAME

    if (
        not force
        and cert_path.is_file()
        and key_path.is_file()
        and cert_path.stat().st_size > 0
        and key_path.stat().st_size > 0
    ):
        return _load_cert_meta(cert_path, key_path)

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, _CN)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=int(validity_days)))
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName("localhost"),
                    x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
                ]
            ),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )

    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)

    # Write key first privately, then cert (replace atomically where possible).
    tmp_key = key_path.with_suffix(key_path.suffix + ".tmp")
    tmp_cert = cert_path.with_suffix(cert_path.suffix + ".tmp")
    try:
        tmp_key.write_bytes(key_pem)
        _chmod_private(tmp_key)
        tmp_cert.write_bytes(cert_pem)
        tmp_key.replace(key_path)
        _chmod_private(key_path)
        tmp_cert.replace(cert_path)
    finally:
        tmp_key.unlink(missing_ok=True)
        tmp_cert.unlink(missing_ok=True)

    return {
        "cert_file": cert_path,
        "key_file": key_path,
        "fingerprint_sha256": cert.fingerprint(hashes.SHA256()).hex(),
        "not_after": cert.not_valid_after_utc,
        "created": True,
    }
