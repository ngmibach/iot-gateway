"""Application-layer envelope v1: dual-part AES-GCM seal/open (psk + ecdhe)."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

PROFILE_PSK = "v1-psk"
PROFILE_ECDHE = "v1-ecdhe"
_ENVELOPE_TOPIC_RE = re.compile(r"^sensors/([^/]+)/env/(key|data)$")


class EnvelopeError(ValueError):
    """Base error for envelope seal/open failures."""

    reason: str = "envelope"


class EnvelopeVersionError(EnvelopeError):
    """Unsupported or mismatched envelope version."""

    reason = "version"


class EnvelopeStampError(EnvelopeError):
    """HMAC binding stamp verification failed."""

    reason = "stamp"


class EnvelopeDayError(EnvelopeError):
    """day_id rejected (skew / allow-list)."""

    reason = "day"


class EnvelopeUnwrapError(EnvelopeError):
    """CEK unwrap failed (wrong wrap material or corrupt wrapped_key)."""

    reason = "unwrap"


class EnvelopeGCMError(EnvelopeError):
    """Content AES-GCM open failed."""

    reason = "gcm"


# Aliases used by decrypt_worker / labs
StampError = EnvelopeStampError
DayError = EnvelopeDayError
UnwrapError = EnvelopeUnwrapError
VersionError = EnvelopeVersionError


@dataclass
class DeviceSecrets:
    device_id: str
    profile: str  # v1-psk | v1-ecdhe
    mac_key: bytes  # 32
    wrap_secret: bytes | None = None  # 32 for psk
    schema_id: str = "default"

    def to_json_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "device_id": self.device_id,
            "profile": self.profile,
            "mac_key": b64e(self.mac_key),
            "schema_id": self.schema_id,
        }
        if self.wrap_secret is not None:
            out["wrap_secret"] = b64e(self.wrap_secret)
        return out

    @classmethod
    def from_json_dict(cls, raw: dict[str, Any]) -> "DeviceSecrets":
        wrap = raw.get("wrap_secret")
        return cls(
            device_id=str(raw["device_id"]),
            profile=str(raw.get("profile") or PROFILE_PSK),
            mac_key=b64d(str(raw["mac_key"])),
            wrap_secret=b64d(str(wrap)) if wrap else None,
            schema_id=str(raw.get("schema_id") or "default"),
        )


@dataclass
class SealResult:
    msg_id: str
    day_id: str
    key_part: dict
    data_part: dict


def b64e(data: bytes) -> str:
    """Urlsafe base64 without padding."""
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def b64d(data: str) -> bytes:
    """Decode urlsafe (or std) base64, accepting missing padding."""
    s = data.strip()
    pad = "=" * (-len(s) % 4)
    for decoder in (base64.urlsafe_b64decode, base64.b64decode):
        try:
            return decoder(s + pad)
        except Exception:
            continue
    raise EnvelopeError("invalid base64")


def today_day_id(now: datetime | None = None) -> str:
    """Return YYYYMMDD in the local timezone."""
    dt = now if now is not None else datetime.now()
    return dt.strftime("%Y%m%d")


def allowed_day_ids_for(
    *,
    now: datetime | None = None,
    skew_days: int = 1,
) -> set[str]:
    """Return today ± skew_days as YYYYMMDD (local)."""
    from datetime import timedelta

    dt = now if now is not None else datetime.now()
    out: set[str] = set()
    for d in range(-skew_days, skew_days + 1):
        out.add((dt + timedelta(days=d)).strftime("%Y%m%d"))
    return out


def corrupt_stamp(part: dict[str, Any]) -> dict[str, Any]:
    """Return a copy with a flipped stamp (lab attacks)."""
    out = dict(part)
    stamp = str(out.get("stamp") or "AAAA")
    mid = max(0, len(stamp) // 2)
    flip = "A" if (mid >= len(stamp) or stamp[mid] != "A") else "B"
    if mid < len(stamp):
        out["stamp"] = stamp[:mid] + flip + stamp[mid + 1 :]
    else:
        out["stamp"] = stamp + "X"
    return out


def stamp_canonical(
    msg_id: str,
    day_id: str,
    schema_id: str,
    wrapped_key: str,
    nonce: str,
    ciphertext: str,
) -> bytes:
    """Canonical bytes for the binding HMAC (UTF-8 of pipe-joined wire strings)."""
    return "|".join(
        (msg_id, day_id, schema_id, wrapped_key, nonce, ciphertext)
    ).encode("utf-8")


def _hmac_stamp(mac_key: bytes, canonical: bytes) -> str:
    return b64e(hmac.new(mac_key, canonical, hashlib.sha256).digest())


def _hkdf_wrap_key(*, ikm: bytes, salt: bytes, info: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=16,
        salt=salt,
        info=info,
    ).derive(ikm)


def _aes_gcm_seal(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
    return AESGCM(key).encrypt(nonce, plaintext, aad)


def _aes_gcm_open(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, aad)
    except Exception as exc:  # noqa: BLE001
        raise EnvelopeGCMError("AES-GCM decrypt failed") from exc


def _plaintext_bytes(plaintext: bytes | str | dict) -> bytes:
    if isinstance(plaintext, dict):
        return json.dumps(plaintext, ensure_ascii=False, separators=(",", ":")).encode(
            "utf-8"
        )
    if isinstance(plaintext, str):
        return plaintext.encode("utf-8")
    return bytes(plaintext)


def _wrap_aad(msg_id_raw: bytes, day_id: str) -> bytes:
    return msg_id_raw + day_id.encode("utf-8")


def _content_aad(msg_id_raw: bytes, day_id: str, schema_id: str) -> bytes:
    return msg_id_raw + day_id.encode("utf-8") + schema_id.encode("utf-8")


def _wrap_cek_psk(
    *,
    cek: bytes,
    wrap_secret: bytes,
    day_id: str,
    msg_id_raw: bytes,
) -> tuple[str, str]:
    wrap_key = _hkdf_wrap_key(
        ikm=wrap_secret,
        salt=b"iotgw-v1-psk",
        info=b"wrap|" + day_id.encode("utf-8"),
    )
    wrap_nonce = os.urandom(12)
    wrapped = _aes_gcm_seal(wrap_key, wrap_nonce, cek, _wrap_aad(msg_id_raw, day_id))
    return b64e(wrapped), b64e(wrap_nonce)


def _unwrap_cek_psk(
    *,
    wrapped_key_b64: str,
    wrap_nonce_b64: str,
    wrap_secret: bytes,
    day_id: str,
    msg_id_raw: bytes,
) -> bytes:
    wrap_key = _hkdf_wrap_key(
        ikm=wrap_secret,
        salt=b"iotgw-v1-psk",
        info=b"wrap|" + day_id.encode("utf-8"),
    )
    try:
        return AESGCM(wrap_key).decrypt(
            b64d(wrap_nonce_b64),
            b64d(wrapped_key_b64),
            _wrap_aad(msg_id_raw, day_id),
        )
    except EnvelopeError:
        raise
    except Exception as exc:  # noqa: BLE001
        raise EnvelopeUnwrapError("PSK unwrap failed") from exc


def _wrap_cek_ecdhe(
    *,
    cek: bytes,
    day_public_key: ec.EllipticCurvePublicKey,
    day_id: str,
    msg_id_raw: bytes,
) -> tuple[str, str, str]:
    eph_private = ec.generate_private_key(ec.SECP256R1())
    shared = eph_private.exchange(ec.ECDH(), day_public_key)
    wrap_key = _hkdf_wrap_key(
        ikm=shared,
        salt=b"iotgw-v1-ecdhe",
        info=b"wrap-ecdhe|" + day_id.encode("utf-8"),
    )
    wrap_nonce = os.urandom(12)
    wrapped = _aes_gcm_seal(wrap_key, wrap_nonce, cek, _wrap_aad(msg_id_raw, day_id))
    eph_pub = eph_private.public_key().public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint,
    )
    return b64e(wrapped), b64e(wrap_nonce), b64e(eph_pub)


def _unwrap_cek_ecdhe(
    *,
    wrapped_key_b64: str,
    wrap_nonce_b64: str,
    eph_pub_b64: str,
    day_private_key: ec.EllipticCurvePrivateKey,
    day_id: str,
    msg_id_raw: bytes,
) -> bytes:
    try:
        eph_pub = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), b64d(eph_pub_b64)
        )
        shared = day_private_key.exchange(ec.ECDH(), eph_pub)
        wrap_key = _hkdf_wrap_key(
            ikm=shared,
            salt=b"iotgw-v1-ecdhe",
            info=b"wrap-ecdhe|" + day_id.encode("utf-8"),
        )
        return AESGCM(wrap_key).decrypt(
            b64d(wrap_nonce_b64),
            b64d(wrapped_key_b64),
            _wrap_aad(msg_id_raw, day_id),
        )
    except EnvelopeError:
        raise
    except Exception as exc:  # noqa: BLE001
        raise EnvelopeUnwrapError("ECDHE unwrap failed") from exc


def generate_device_secrets(
    device_id: str,
    *,
    profile: str = PROFILE_PSK,
    schema_id: str = "default",
) -> DeviceSecrets:
    if profile not in (PROFILE_PSK, PROFILE_ECDHE):
        raise ValueError(f"unsupported profile: {profile}")
    wrap_secret = os.urandom(32) if profile == PROFILE_PSK else None
    return DeviceSecrets(
        device_id=device_id,
        profile=profile,
        mac_key=os.urandom(32),
        wrap_secret=wrap_secret,
        schema_id=schema_id,
    )


def seal(
    plaintext: bytes | str | dict,
    secrets: DeviceSecrets,
    *,
    day_id: str | None = None,
    day_public_key: ec.EllipticCurvePublicKey | None = None,
) -> SealResult:
    """Seal plaintext into dual key/data envelope parts."""
    if secrets.profile not in (PROFILE_PSK, PROFILE_ECDHE):
        raise EnvelopeVersionError(f"unsupported profile: {secrets.profile}")
    if day_id is None:
        day_id = today_day_id()

    msg_id_raw = os.urandom(16)
    msg_id = b64e(msg_id_raw)
    cek = os.urandom(16)
    nonce_raw = os.urandom(12)
    plain = _plaintext_bytes(plaintext)
    ciphertext_raw = _aes_gcm_seal(
        cek,
        nonce_raw,
        plain,
        _content_aad(msg_id_raw, day_id, secrets.schema_id),
    )
    nonce = b64e(nonce_raw)
    ciphertext = b64e(ciphertext_raw)

    key_part: dict[str, Any] = {
        "v": 1,
        "msg_id": msg_id,
        "day_id": day_id,
        "schema_id": secrets.schema_id,
        "alg": secrets.profile,
    }

    if secrets.profile == PROFILE_PSK:
        if not secrets.wrap_secret:
            raise EnvelopeUnwrapError("wrap_secret required for v1-psk")
        wrapped_key, wrap_nonce = _wrap_cek_psk(
            cek=cek,
            wrap_secret=secrets.wrap_secret,
            day_id=day_id,
            msg_id_raw=msg_id_raw,
        )
        key_part["wrapped_key"] = wrapped_key
        key_part["wrap_nonce"] = wrap_nonce
    else:
        if day_public_key is None:
            raise EnvelopeUnwrapError("day_public_key required for v1-ecdhe")
        wrapped_key, wrap_nonce, eph_pub = _wrap_cek_ecdhe(
            cek=cek,
            day_public_key=day_public_key,
            day_id=day_id,
            msg_id_raw=msg_id_raw,
        )
        key_part["wrapped_key"] = wrapped_key
        key_part["wrap_nonce"] = wrap_nonce
        key_part["eph_pub"] = eph_pub

    stamp = _hmac_stamp(
        secrets.mac_key,
        stamp_canonical(
            msg_id,
            day_id,
            secrets.schema_id,
            key_part["wrapped_key"],
            nonce,
            ciphertext,
        ),
    )
    key_part["stamp"] = stamp
    data_part = {
        "v": 1,
        "msg_id": msg_id,
        "day_id": day_id,
        "nonce": nonce,
        "ciphertext": ciphertext,
        "stamp": stamp,
    }
    return SealResult(
        msg_id=msg_id,
        day_id=day_id,
        key_part=key_part,
        data_part=data_part,
    )


def open_envelope(
    key_part: dict,
    data_part: dict,
    secrets: DeviceSecrets,
    *,
    day_private_key: ec.EllipticCurvePrivateKey | None = None,
    allowed_day_ids: set[str] | None = None,
) -> bytes:
    """Open a dual-part envelope; return plaintext bytes."""
    if key_part.get("v") != 1 or data_part.get("v") != 1:
        raise EnvelopeVersionError("unsupported envelope version")

    msg_id = key_part.get("msg_id")
    if not msg_id or msg_id != data_part.get("msg_id"):
        raise EnvelopeStampError("msg_id mismatch between key and data parts")

    day_id = key_part.get("day_id")
    if not day_id or day_id != data_part.get("day_id"):
        raise EnvelopeDayError("day_id mismatch between key and data parts")

    allowed = (
        allowed_day_ids if allowed_day_ids is not None else allowed_day_ids_for()
    )
    if day_id not in allowed:
        raise EnvelopeDayError(f"day_id not allowed: {day_id}")

    schema_id = key_part.get("schema_id") or secrets.schema_id
    alg = key_part.get("alg") or secrets.profile
    if alg not in (PROFILE_PSK, PROFILE_ECDHE):
        raise EnvelopeVersionError(f"unsupported alg: {alg}")

    wrapped_key = key_part.get("wrapped_key")
    nonce = data_part.get("nonce")
    ciphertext = data_part.get("ciphertext")
    if not wrapped_key or not nonce or not ciphertext:
        raise EnvelopeError("missing wrapped_key, nonce, or ciphertext")

    expected = _hmac_stamp(
        secrets.mac_key,
        stamp_canonical(msg_id, day_id, schema_id, wrapped_key, nonce, ciphertext),
    )
    key_stamp = key_part.get("stamp") or ""
    data_stamp = data_part.get("stamp") or ""
    if not (
        hmac.compare_digest(key_stamp, expected)
        and hmac.compare_digest(data_stamp, expected)
    ):
        raise EnvelopeStampError("stamp verification failed")

    try:
        msg_id_raw = b64d(msg_id)
    except EnvelopeError as exc:
        raise EnvelopeError("invalid msg_id encoding") from exc

    wrap_nonce = key_part.get("wrap_nonce")
    if not wrap_nonce:
        raise EnvelopeUnwrapError("missing wrap_nonce")

    if alg == PROFILE_PSK:
        if not secrets.wrap_secret:
            raise EnvelopeUnwrapError("wrap_secret required for v1-psk")
        cek = _unwrap_cek_psk(
            wrapped_key_b64=wrapped_key,
            wrap_nonce_b64=wrap_nonce,
            wrap_secret=secrets.wrap_secret,
            day_id=day_id,
            msg_id_raw=msg_id_raw,
        )
    else:
        if day_private_key is None:
            raise EnvelopeUnwrapError("day_private_key required for v1-ecdhe")
        eph_pub = key_part.get("eph_pub")
        if not eph_pub:
            raise EnvelopeUnwrapError("missing eph_pub")
        cek = _unwrap_cek_ecdhe(
            wrapped_key_b64=wrapped_key,
            wrap_nonce_b64=wrap_nonce,
            eph_pub_b64=eph_pub,
            day_private_key=day_private_key,
            day_id=day_id,
            msg_id_raw=msg_id_raw,
        )

    if len(cek) != 16:
        raise EnvelopeUnwrapError(f"unexpected CEK length: {len(cek)}")

    try:
        return _aes_gcm_open(
            cek,
            b64d(nonce),
            b64d(ciphertext),
            _content_aad(msg_id_raw, day_id, schema_id),
        )
    except EnvelopeGCMError:
        raise
    except Exception as exc:  # noqa: BLE001
        raise EnvelopeGCMError("content decrypt failed") from exc


def key_topic(device_id: str) -> str:
    return f"sensors/{device_id}/env/key"


def data_topic(device_id: str) -> str:
    return f"sensors/{device_id}/env/data"


def parse_envelope_topic(topic: str) -> tuple[str, str] | None:
    """Parse ``sensors/{id}/env/key|data`` → ``(device_id, \"key\"|\"data\")``."""
    m = _ENVELOPE_TOPIC_RE.match(topic)
    if not m:
        return None
    return m.group(1), m.group(2)
