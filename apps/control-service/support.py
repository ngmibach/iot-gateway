"""Sanitized support-bundle export (no secrets / PEMs / keyring material)."""

from __future__ import annotations

import io
import json
import os
import re
import tarfile
import time
import zipfile
from pathlib import Path
from typing import Any, Mapping, Optional

# Values for these keys are always replaced (case-insensitive, nested).
SECRET_KEY_FRAGMENTS = (
    "password",
    "passwd",
    "passphrase",
    "secret",
    "token",
    "api_key",
    "apikey",
    "private_key",
    "privkey",
    "ssh_key",
    "ca_pass",
    "keyring",
    "credential",
    "auth_header",
    "authorization",
)

REDACTED = "[REDACTED]"

_PEM_RE = re.compile(
    r"-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----"
    r"|-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----"
    r"|-----BEGIN ENCRYPTED PRIVATE KEY-----.*?-----END ENCRYPTED PRIVATE KEY-----",
    re.DOTALL | re.IGNORECASE,
)

_BEARER_RE = re.compile(r"(Bearer\s+)(\S+)", re.IGNORECASE)
_PASS_ARGV_RE = re.compile(
    r"(-pass(?:in|out)\s+(?:pass|file):)\S+",
    re.IGNORECASE,
)


def _key_is_secret(key: str) -> bool:
    lowered = key.lower().replace("-", "_")
    # Paths/filenames are safe to export; file *contents* are not in settings.
    if lowered.endswith("_path") or lowered.endswith("_file") or lowered.endswith("_dir"):
        return any(
            frag in lowered
            for frag in ("password", "passwd", "passphrase", "token", "secret")
        )
    return any(frag in lowered for frag in SECRET_KEY_FRAGMENTS)


def redact_string(text: str) -> str:
    """Strip PEMs and common secret argv / bearer forms from free text."""
    if not text:
        return text
    out = _PEM_RE.sub(REDACTED, text)
    out = _BEARER_RE.sub(rf"\1{REDACTED}", out)
    out = _PASS_ARGV_RE.sub(rf"\1{REDACTED}", out)
    return out


def _maybe_parse_json(text: str) -> Any:
    s = text.strip()
    if not s or s[0] not in "{[":
        return None
    try:
        return json.loads(s)
    except (json.JSONDecodeError, TypeError):
        return None


def redact_value(value: Any, *, key: str | None = None) -> Any:
    """Recursively redact mappings/lists/strings; never echo secret fields."""
    if key is not None and _key_is_secret(key):
        if value is None or value == "":
            return value
        return REDACTED
    if isinstance(value, Mapping):
        return {k: redact_value(v, key=str(k)) for k, v in value.items()}
    if isinstance(value, list):
        return [redact_value(v) for v in value]
    if isinstance(value, tuple):
        return tuple(redact_value(v) for v in value)
    if isinstance(value, str):
        parsed = _maybe_parse_json(value)
        if parsed is not None:
            # Re-serialize so nested secret keys inside detail_json are wiped
            return json.dumps(
                redact_value(parsed), ensure_ascii=False, separators=(",", ":")
            )
        return redact_string(value)
    return value


def settings_public(settings: Any) -> dict[str, Any]:
    """Serialize Settings-like object with secrets removed."""
    if hasattr(settings, "__dataclass_fields__"):
        raw = {f: getattr(settings, f) for f in settings.__dataclass_fields__}
    elif isinstance(settings, Mapping):
        raw = dict(settings)
    else:
        raw = {
            k: getattr(settings, k)
            for k in dir(settings)
            if not k.startswith("_") and not callable(getattr(settings, k, None))
        }
    # Paths → str for JSON
    out: dict[str, Any] = {}
    for k, v in raw.items():
        if isinstance(v, Path):
            out[k] = str(v)
        else:
            out[k] = v
    return redact_value(out)  # type: ignore[return-value]


def _safe_json_bytes(obj: Any) -> bytes:
    return json.dumps(obj, indent=2, ensure_ascii=False, default=str).encode("utf-8")


def collect_bundle_payload(
    *,
    settings: Any = None,
    registry: Any = None,
    gateway_status: Optional[Mapping[str, Any]] = None,
    control_logs: Optional[str] = None,
    log_path: Optional[Path] = None,
    extra: Optional[Mapping[str, Any]] = None,
    audit_limit: int = 200,
) -> dict[str, Any]:
    """Build the in-memory support payload (already redacted)."""
    created = int(time.time())
    payload: dict[str, Any] = {
        "meta": {
            "created_at": created,
            "format": "iotgw-support-bundle/v1",
            "note": "Secrets, PEMs, and keyring material are redacted.",
        },
        "settings": settings_public(settings) if settings is not None else {},
        "gateways": [],
        "devices": [],
        "audit_log": [],
        "gateway_status": redact_value(dict(gateway_status or {})),
        "extra": redact_value(dict(extra or {})),
    }

    if registry is not None:
        try:
            gateways = registry.list_gateways()
        except Exception as exc:  # pragma: no cover - defensive
            payload["gateways_error"] = str(exc)
            gateways = []
        payload["gateways"] = redact_value(gateways)
        devices: list[dict[str, Any]] = []
        for gw in gateways:
            gid = gw.get("id")
            if not gid:
                continue
            try:
                devices.extend(registry.list_devices(gid))
            except TypeError:
                devices.extend(registry.list_devices(gateway_id=gid))
            except Exception as exc:  # pragma: no cover
                payload.setdefault("devices_errors", []).append(
                    {"gateway_id": gid, "error": str(exc)}
                )
        payload["devices"] = redact_value(devices)
        try:
            audit = registry.list_audit(limit=audit_limit)
        except Exception as exc:  # pragma: no cover
            payload["audit_error"] = str(exc)
            audit = []
        # Drop any PEM / secret leakage that may have landed in detail_json
        payload["audit_log"] = redact_value(audit)

    log_text = control_logs
    if log_text is None and log_path is not None and Path(log_path).is_file():
        try:
            # Cap size so bundles stay small
            raw = Path(log_path).read_text(encoding="utf-8", errors="replace")
            if len(raw) > 512_000:
                raw = raw[-512_000:]
            log_text = raw
        except OSError as exc:
            payload["control_logs_error"] = str(exc)
            log_text = None
    if log_text is not None:
        payload["control_logs"] = redact_string(log_text)

    return payload


def write_support_bundle(
    dest: Path | str,
    *,
    settings: Any = None,
    registry: Any = None,
    gateway_status: Optional[Mapping[str, Any]] = None,
    control_logs: Optional[str] = None,
    log_path: Optional[Path] = None,
    extra: Optional[Mapping[str, Any]] = None,
    fmt: str = "zip",
) -> Path:
    """Write a sanitized support archive to ``dest`` (``.zip`` or ``.tar.gz``).

    Returns the path written. Contents:
    - ``meta.json`` / ``settings.json`` / ``registry.json`` / ``gateway_status.json``
    - ``audit_log.json``
    - ``control.log`` (redacted) when available
    """
    dest_path = Path(dest)
    payload = collect_bundle_payload(
        settings=settings,
        registry=registry,
        gateway_status=gateway_status,
        control_logs=control_logs,
        log_path=log_path,
        extra=extra,
    )

    files: dict[str, bytes] = {
        "meta.json": _safe_json_bytes(payload["meta"]),
        "settings.json": _safe_json_bytes(payload.get("settings") or {}),
        "registry.json": _safe_json_bytes(
            {
                "gateways": payload.get("gateways") or [],
                "devices": payload.get("devices") or [],
            }
        ),
        "audit_log.json": _safe_json_bytes(payload.get("audit_log") or []),
        "gateway_status.json": _safe_json_bytes(payload.get("gateway_status") or {}),
        "extra.json": _safe_json_bytes(payload.get("extra") or {}),
    }
    if "control_logs" in payload:
        files["control.log"] = str(payload["control_logs"]).encode("utf-8")

    dest_path.parent.mkdir(parents=True, exist_ok=True)
    fmt_norm = fmt.lower().strip()
    if fmt_norm in ("tar", "tar.gz", "tgz"):
        if not str(dest_path).endswith((".tar.gz", ".tgz")):
            dest_path = dest_path.with_suffix(dest_path.suffix + ".tar.gz")
        with tarfile.open(dest_path, "w:gz") as tar:
            for name, data in files.items():
                info = tarfile.TarInfo(name=name)
                info.size = len(data)
                info.mtime = int(time.time())
                tar.addfile(info, io.BytesIO(data))
    else:
        if dest_path.suffix.lower() != ".zip":
            dest_path = dest_path.with_suffix(".zip")
        with zipfile.ZipFile(dest_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            for name, data in files.items():
                zf.writestr(name, data)

    return dest_path


def bundle_contains_forbidden(archive: Path | str) -> list[str]:
    """Return list of forbidden substrings found (for tests / CI checks)."""
    path = Path(archive)
    hits: list[str] = []
    forbidden = (
        "BEGIN PRIVATE KEY",
        "BEGIN RSA PRIVATE KEY",
        "BEGIN ENCRYPTED PRIVATE KEY",
        "BEGIN CERTIFICATE",
    )
    data = path.read_bytes()
    # Also open members so binary zip local headers don't matter
    texts: list[str] = []
    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as zf:
            for name in zf.namelist():
                texts.append(zf.read(name).decode("utf-8", errors="replace"))
    elif tarfile.is_tarfile(path):
        with tarfile.open(path, "r:*") as tar:
            for m in tar.getmembers():
                if not m.isfile():
                    continue
                f = tar.extractfile(m)
                if f is not None:
                    texts.append(f.read().decode("utf-8", errors="replace"))
    else:
        texts.append(data.decode("utf-8", errors="replace"))

    blob = "\n".join(texts)
    for marker in forbidden:
        if marker in blob:
            hits.append(marker)
    # Plain secret values that should never appear after redaction when tests
    # inject known markers — callers check those separately.
    return hits


def default_bundle_path(data_dir: Path | str | None = None) -> Path:
    base = Path(data_dir) if data_dir else Path(
        os.environ.get("IOTGW_DATA_DIR", "").strip()
        or (Path.home() / ".local" / "share" / "iot-gateway-monitor")
    )
    ts = time.strftime("%Y%m%d-%H%M%S")
    return base / "support" / f"iotgw-support-{ts}.zip"
