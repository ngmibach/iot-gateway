"""Provision per-device envelope secrets + schemas on the gateway (SSH)."""

from __future__ import annotations

import base64
import json
import os
from typing import TYPE_CHECKING, Any, Optional

from .paths import DEFAULT_AGENT_DATA, DEFAULT_INSTALL_ROOT, GatewayPaths
from .shellutil import shell_quote
from .validate import validate_user_id

if TYPE_CHECKING:
    from .ssh import SSHClient

PROFILE_PSK = "v1-psk"
PROFILE_ECDHE = "v1-ecdhe"
SUPPORTED_PROFILES = frozenset({PROFILE_PSK, PROFILE_ECDHE})

DEFAULT_SCHEMA: dict[str, Any] = {
    "schema_id": "default",
    "type": "object",
    "additionalProperties": True,
    "properties": {},
}

# Stricter lab schema for fake sensors (supports schema attack toggles).
FAKE_DEFAULT_SCHEMA: dict[str, Any] = {
    "schema_id": "default",
    "type": "object",
    "additionalProperties": False,
    "required": ["device_id"],
    "properties": {
        "device_id": {"type": "string", "const": "@device_id"},
        "hello": {"type": "integer"},
        "temp_c": {"type": "number"},
        "ts_ms": {"type": "integer"},
        "ok": {"type": "boolean"},
        "delay": {"type": "number"},
        "error": {"type": "string"},
    },
}


def _b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _paths(
    install_root: str = DEFAULT_INSTALL_ROOT,
    data_dir: str | None = None,
) -> GatewayPaths:
    return GatewayPaths(
        install_root=install_root,
        data_dir=data_dir if data_dir is not None else DEFAULT_AGENT_DATA,
    )


def generate_device_crypto_dict(
    device_id: str,
    *,
    profile: str = PROFILE_PSK,
    schema_id: str = "default",
) -> dict[str, Any]:
    """Generate envelope secrets JSON (matches agent DeviceSecrets.to_json_dict)."""
    device_id = validate_user_id(device_id)
    if profile not in SUPPORTED_PROFILES:
        raise ValueError(f"unsupported crypto profile: {profile}")
    out: dict[str, Any] = {
        "device_id": device_id,
        "profile": profile,
        "mac_key": _b64e(os.urandom(32)),
        "schema_id": schema_id or "default",
    }
    if profile == PROFILE_PSK:
        out["wrap_secret"] = _b64e(os.urandom(32))
    return out


def device_crypto_remote_path(paths: GatewayPaths, device_id: str) -> str:
    return f"{paths.data_dir}/crypto/devices/{device_id}.json"


def schema_remote_path(paths: GatewayPaths, schema_id: str) -> str:
    safe = "".join(c for c in schema_id if c.isalnum() or c in ("-", "_", "."))
    if not safe:
        raise ValueError("invalid schema_id")
    return f"{paths.data_dir}/schemas/{safe}.json"


def provision_device_crypto(
    ssh: "SSHClient",
    device_id: str,
    *,
    profile: str = PROFILE_PSK,
    schema_id: str = "default",
    schema: dict[str, Any] | None = None,
    install_root: str = DEFAULT_INSTALL_ROOT,
    data_dir: str | None = None,
    also_fake_copy: bool = False,
) -> dict[str, Any]:
    """Write device crypto JSON (+ schema) on the gateway; return secrets dict."""
    device_id = validate_user_id(device_id)
    paths = _paths(install_root, data_dir)
    secrets = generate_device_crypto_dict(
        device_id, profile=profile, schema_id=schema_id
    )
    crypto_path = device_crypto_remote_path(paths, device_id)
    ssh.run(f"mkdir -p {shell_quote(paths.data_dir + '/crypto/devices')}")
    ssh.write_text(
        crypto_path,
        json.dumps(secrets, indent=2, sort_keys=True) + "\n",
        mode=0o600,
    )

    schema_body = dict(schema) if isinstance(schema, dict) else dict(DEFAULT_SCHEMA)
    schema_body["schema_id"] = schema_id or schema_body.get("schema_id") or "default"
    sch_path = schema_remote_path(paths, schema_body["schema_id"])
    ssh.run(f"mkdir -p {shell_quote(paths.data_dir + '/schemas')}")
    ssh.write_text(
        sch_path,
        json.dumps(schema_body, indent=2, sort_keys=True) + "\n",
        mode=0o644,
    )

    if also_fake_copy:
        fake_crypto = f"{paths.data_dir}/fake/{device_id}/crypto.json"
        ssh.run(f"mkdir -p {shell_quote(paths.data_dir + '/fake/' + device_id)}")
        ssh.write_text(
            fake_crypto,
            json.dumps(secrets, indent=2, sort_keys=True) + "\n",
            mode=0o600,
        )

    return {
        "secrets": secrets,
        "crypto_path": crypto_path,
        "schema_path": sch_path,
        "schema_id": schema_body["schema_id"],
        "profile": profile,
    }


def assemble_cert_bundle(
    *,
    ca_crt_pem: bytes,
    client_crt_pem: bytes,
    client_key_pem: bytes,
    crypto_json: dict[str, Any] | None = None,
    schema_json: dict[str, Any] | None = None,
) -> bytes:
    """Zip PEMs plus optional envelope crypto.json / schema.json."""
    import io
    import zipfile

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("ca.crt", ca_crt_pem)
        zf.writestr("client.crt", client_crt_pem)
        zf.writestr("client.key", client_key_pem)
        if crypto_json is not None:
            zf.writestr(
                "crypto.json",
                json.dumps(crypto_json, indent=2, sort_keys=True) + "\n",
            )
        if schema_json is not None:
            zf.writestr(
                "schema.json",
                json.dumps(schema_json, indent=2, sort_keys=True) + "\n",
            )
    return buf.getvalue()
