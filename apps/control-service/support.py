"""Sanitized support-bundle export (no secrets / private PEMs / keyring material)."""

from __future__ import annotations

import json
import os
import re
import time
import zipfile
from pathlib import Path
from typing import Any, Mapping, Optional, Sequence

REDACTED = "[REDACTED]"

# Exact key names that look secret-ish but are safe diagnostics.
_SECRET_KEY_ALLOWLIST = frozenset(
    {
        "password_auth_enabled",
    }
)

# Whole-key names treated as secrets (after lower/underscore normalize).
_SECRET_KEYS_EXACT = frozenset(
    {
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
        "ca_passphrase",
        "keyring",
        "credential",
        "credentials",
        "auth_header",
        "authorization",
        "basic_auth",
        "signing_key",
        "client_secret",
        "api_token",
        "ssh_password",
    }
)

# Suffixes that mark a key as secret (e.g. mqtt_password, refresh_token).
_SECRET_KEY_SUFFIXES = (
    "_password",
    "_passwd",
    "_passphrase",
    "_secret",
    "_token",
    "_api_key",
    "_apikey",
    "_private_key",
    "_privkey",
    "_credential",
    "_credentials",
    "_basic_auth",
    "_signing_key",
    "_ca_pass",
)

# Private key PEM only — public certificates stay for TLS debugging.
_PEM_PRIVATE_RE = re.compile(
    r"-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----",
    re.DOTALL | re.IGNORECASE,
)

_BEARER_RE = re.compile(r"(Bearer\s+)\S+", re.IGNORECASE)
_PASS_ARGV_RE = re.compile(
    r"(-pass(?:in|out)\s+(?:pass|file|env):)\S+",
    re.IGNORECASE,
)

# Value-aware: \b so password_auth_enabled=1 is not matched as password=.
_ASSIGN_SECRET_RE = re.compile(
    r"(?i)\b(password|passwd|passphrase|token|secret|api[_-]?key|apikey)"
    r"\b\s*[=:]\s*\S+"
)
_IOTGW_ENV_SECRET_RE = re.compile(
    r"(?i)\b(IOTGW_(?:API_TOKEN|SSH_PASSWORD|CA_PASSPHRASE|SSH_KEY))\s*=\s*\S+"
)


def _key_is_secret(key: str) -> bool:
    lowered = key.lower().replace("-", "_")
    if lowered in _SECRET_KEY_ALLOWLIST:
        return False
    # Paths/filenames are safe to export; file contents are not in settings.
    if lowered.endswith(("_path", "_file", "_dir")):
        return any(
            lowered == s or lowered.endswith(s)
            for s in (
                "_password",
                "_passwd",
                "_passphrase",
                "_token",
                "_secret",
            )
        ) or lowered in {"password", "passwd", "passphrase", "token", "secret"}
    if lowered in _SECRET_KEYS_EXACT:
        return True
    return any(lowered.endswith(suf) for suf in _SECRET_KEY_SUFFIXES)


def redact_string(text: str) -> str:
    """Strip private PEMs and common secret argv / env / assignment forms."""
    if not text:
        return text
    out = _PEM_PRIVATE_RE.sub(REDACTED, text)
    out = _BEARER_RE.sub(rf"\1{REDACTED}", out)
    out = _PASS_ARGV_RE.sub(rf"\1{REDACTED}", out)
    out = _IOTGW_ENV_SECRET_RE.sub(lambda m: f"{m.group(1)}={REDACTED}", out)
    out = _ASSIGN_SECRET_RE.sub(
        lambda m: f"{m.group(1)}={REDACTED}",
        out,
    )
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
            return json.dumps(
                redact_value(parsed), ensure_ascii=False, separators=(",", ":")
            )
        return redact_string(value)
    return value


def settings_public(settings: Any) -> dict[str, Any]:
    """Serialize Settings dataclass or mapping with secrets removed."""
    if hasattr(settings, "__dataclass_fields__"):
        raw = {f: getattr(settings, f) for f in settings.__dataclass_fields__}
    elif isinstance(settings, Mapping):
        raw = dict(settings)
    else:
        raise TypeError(
            "settings_public expects a dataclass or mapping, "
            f"got {type(settings).__name__}"
        )
    out: dict[str, Any] = {}
    for k, v in raw.items():
        out[k] = str(v) if isinstance(v, Path) else v
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
            "note": "Secrets, private PEMs, and keyring material are redacted.",
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
        payload["audit_log"] = redact_value(audit)

    log_text = control_logs
    if log_text is None and log_path is not None and Path(log_path).is_file():
        try:
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
) -> Path:
    """Write a sanitized support ``.zip`` to ``dest``. Returns the path written."""
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
    if dest_path.suffix.lower() != ".zip":
        dest_path = dest_path.with_suffix(".zip")
    with zipfile.ZipFile(dest_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, data in files.items():
            zf.writestr(name, data)
    return dest_path


def bundle_contains_forbidden(
    archive: Path | str,
    *,
    forbidden_substrings: Optional[Sequence[str]] = None,
) -> list[str]:
    """Return forbidden markers found in zip members (for tests / CI)."""
    path = Path(archive)
    markers = list(forbidden_substrings) if forbidden_substrings is not None else [
        "BEGIN PRIVATE KEY",
        "BEGIN RSA PRIVATE KEY",
        "BEGIN ENCRYPTED PRIVATE KEY",
        "BEGIN OPENSSH PRIVATE KEY",
    ]
    texts: list[str] = []
    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as zf:
            for name in zf.namelist():
                texts.append(zf.read(name).decode("utf-8", errors="replace"))
    else:
        texts.append(path.read_bytes().decode("utf-8", errors="replace"))

    blob = "\n".join(texts)
    return [m for m in markers if m in blob]


def default_bundle_path(data_dir: Path | str | None = None) -> Path:
    base = Path(data_dir) if data_dir else Path(
        os.environ.get("IOTGW_DATA_DIR", "").strip()
        or (Path.home() / ".local" / "share" / "iot-gateway-monitor")
    )
    ts = time.strftime("%Y%m%d-%H%M%S")
    return base / "support" / f"iotgw-support-{ts}.zip"
