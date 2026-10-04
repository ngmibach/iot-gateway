"""Test-only cert helpers (not shipped in actions/)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from actions.csr import ClientKeyMaterial, SignedClientCert


def local_self_sign_for_tests(
    material: ClientKeyMaterial,
    *,
    days: int = 30,
) -> SignedClientCert:
    key = serialization.load_pem_private_key(material.private_key_pem, password=None)
    csr = x509.load_pem_x509_csr(material.csr_pem)
    assert isinstance(key, rsa.RSAPrivateKey)
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(csr.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=days))
        .sign(key, hashes.SHA256())
    )
    pem = cert.public_bytes(serialization.Encoding.PEM)
    return SignedClientCert(
        client_crt_pem=pem,
        ca_crt_pem=pem,
        not_valid_after=cert.not_valid_after_utc,
        fingerprint_sha256=cert.fingerprint(hashes.SHA256()).hex(),
    )
