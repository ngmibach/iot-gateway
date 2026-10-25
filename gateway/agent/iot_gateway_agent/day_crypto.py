"""Daily Message Encryption Certificate (DMEC) issue / load for envelope v1-ecdhe."""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from .envelope_v1 import today_day_id

logger = logging.getLogger(__name__)


def day_dir(data_dir: str | Path) -> Path:
    return Path(data_dir) / "certs" / "day"


def day_cert_path(data_dir: str | Path, day_id: str) -> Path:
    return day_dir(data_dir) / f"{day_id}.crt"


def day_key_path(data_dir: str | Path, day_id: str) -> Path:
    return day_dir(data_dir) / f"{day_id}.key"


def load_day_private_key(
    data_dir: str | Path, day_id: str
) -> ec.EllipticCurvePrivateKey | None:
    path = day_key_path(data_dir, day_id)
    if not path.is_file():
        return None
    try:
        key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    except Exception as exc:  # noqa: BLE001
        logger.warning("failed to load day key %s: %s", path, exc)
        return None
    if not isinstance(key, ec.EllipticCurvePrivateKey):
        return None
    return key


def load_day_public_key(
    data_dir: str | Path, day_id: str
) -> ec.EllipticCurvePublicKey | None:
    path = day_cert_path(data_dir, day_id)
    if not path.is_file():
        return None
    try:
        cert = x509.load_pem_x509_certificate(path.read_bytes())
    except Exception as exc:  # noqa: BLE001
        logger.warning("failed to load day cert %s: %s", path, exc)
        return None
    pub = cert.public_key()
    if not isinstance(pub, ec.EllipticCurvePublicKey):
        return None
    return pub


def load_day_cert_pem(data_dir: str | Path, day_id: str) -> bytes | None:
    path = day_cert_path(data_dir, day_id)
    if not path.is_file():
        return None
    return path.read_bytes()


def ensure_day_material(
    data_dir: str | Path,
    *,
    ca_cert_path: str | Path | None = None,
    ca_key_path: str | Path | None = None,
    ca_passphrase: bytes | str | None = None,
    day_id: str | None = None,
    validity_hours: int = 36,
) -> dict:
    """Ensure DMEC key+cert exist for ``day_id`` (default today).

    When CA key is available, the day cert is CA-signed. Otherwise a
    self-signed day cert is written so PSK-only gateways still have a day_id
    artifact and ECDHE can be tested in lab.
    """
    did = day_id or today_day_id()
    ddir = day_dir(data_dir)
    ddir.mkdir(parents=True, exist_ok=True)
    crt_path = day_cert_path(data_dir, did)
    key_path = day_key_path(data_dir, did)
    if crt_path.is_file() and key_path.is_file():
        return {
            "day_id": did,
            "cert_path": str(crt_path),
            "key_path": str(key_path),
            "created": False,
        }

    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    now = datetime.now(timezone.utc)
    # Cover previous evening → next afternoon for skew.
    not_before = now - timedelta(hours=1)
    not_after = now + timedelta(hours=max(24, validity_hours))

    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, f"iotgw-day-{did}"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "iot-gateway-agent"),
        ]
    )

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(f"day-{did}.iotgw.local")]),
            critical=False,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=True,
                key_agreement=True,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    )

    ca_key = None
    ca_cert = None
    if ca_key_path and Path(ca_key_path).is_file() and ca_cert_path and Path(ca_cert_path).is_file():
        pass_bytes: bytes | None
        if ca_passphrase is None:
            pass_bytes = None
        elif isinstance(ca_passphrase, bytes):
            pass_bytes = ca_passphrase
        else:
            pass_bytes = ca_passphrase.encode("utf-8") if ca_passphrase else None
        try:
            ca_key = serialization.load_pem_private_key(
                Path(ca_key_path).read_bytes(), password=pass_bytes
            )
            ca_cert = x509.load_pem_x509_certificate(Path(ca_cert_path).read_bytes())
            builder = builder.issuer_name(ca_cert.subject)
        except Exception as exc:  # noqa: BLE001
            logger.warning("day cert CA sign unavailable (%s); self-signing", exc)
            ca_key = None
            ca_cert = None

    signer = ca_key if ca_key is not None else private_key
    cert = builder.sign(private_key=signer, algorithm=hashes.SHA256())

    key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    crt_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_path.write_bytes(key_pem)
    key_path.chmod(0o600)
    crt_path.write_bytes(crt_pem)
    crt_path.chmod(0o644)
    logger.info("issued day material day_id=%s ca_signed=%s", did, ca_cert is not None)
    return {
        "day_id": did,
        "cert_path": str(crt_path),
        "key_path": str(key_path),
        "created": True,
        "ca_signed": ca_cert is not None,
    }


def resolve_day_private_key(
    data_dir: str | Path,
    day_id: str,
    *,
    cache: dict[str, ec.EllipticCurvePrivateKey] | None = None,
) -> ec.EllipticCurvePrivateKey | None:
    if cache is not None and day_id in cache:
        return cache[day_id]
    key = load_day_private_key(data_dir, day_id)
    if key is not None and cache is not None:
        cache[day_id] = key
    return key
