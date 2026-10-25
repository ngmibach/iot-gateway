"""On-disk device envelope secrets and message schemas for the gateway agent."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Optional

from .envelope_v1 import DeviceSecrets
from .schema_validate import SchemaError, load_schema, validate_payload

logger = logging.getLogger(__name__)


def crypto_devices_dir(data_dir: str | Path) -> Path:
    return Path(data_dir) / "crypto" / "devices"


def schemas_dir(data_dir: str | Path) -> Path:
    return Path(data_dir) / "schemas"


def device_crypto_path(data_dir: str | Path, device_id: str) -> Path:
    return crypto_devices_dir(data_dir) / f"{device_id}.json"


def schema_path(data_dir: str | Path, schema_id: str) -> Path:
    safe = "".join(c for c in schema_id if c.isalnum() or c in ("-", "_", "."))
    if not safe:
        raise ValueError("invalid schema_id")
    return schemas_dir(data_dir) / f"{safe}.json"


def save_device_secrets(data_dir: str | Path, secrets: DeviceSecrets) -> Path:
    root = crypto_devices_dir(data_dir)
    root.mkdir(parents=True, exist_ok=True)
    path = device_crypto_path(data_dir, secrets.device_id)
    path.write_text(
        json.dumps(secrets.to_json_dict(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    path.chmod(0o600)
    return path


def load_device_secrets(
    data_dir: str | Path, device_id: str
) -> DeviceSecrets | None:
    path = device_crypto_path(data_dir, device_id)
    if not path.is_file():
        return None
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("device crypto load failed for %s: %s", device_id, exc)
        return None
    if not isinstance(raw, dict):
        return None
    try:
        return DeviceSecrets.from_json_dict(raw)
    except Exception as exc:  # noqa: BLE001
        logger.warning("device crypto parse failed for %s: %s", device_id, exc)
        return None


def save_schema(
    data_dir: str | Path, schema_id: str, schema: dict[str, Any]
) -> Path:
    root = schemas_dir(data_dir)
    root.mkdir(parents=True, exist_ok=True)
    body = dict(schema)
    body.setdefault("schema_id", schema_id)
    path = schema_path(data_dir, schema_id)
    path.write_text(json.dumps(body, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    path.chmod(0o644)
    return path


def load_device_schema(
    data_dir: str | Path, schema_id: str
) -> dict[str, Any] | None:
    path = schema_path(data_dir, schema_id)
    if not path.is_file():
        return None
    try:
        return load_schema(path)
    except Exception as exc:  # noqa: BLE001
        logger.warning("schema load failed %s: %s", schema_id, exc)
        return None


DEFAULT_SCHEMA: dict[str, Any] = {
    "schema_id": "default",
    "type": "object",
    "additionalProperties": True,
    "properties": {},
}


def validate_cleartext(
    data_dir: str | Path,
    *,
    device_id: str,
    schema_id: str,
    clear_json: str | bytes | dict[str, Any],
    require_schema_file: bool = False,
) -> None:
    """Validate decrypted JSON against registered schema.

    Missing schema file: allow if ``require_schema_file`` is False and schema_id
    is ``default`` (permissive). Otherwise raise SchemaError.
    """
    if isinstance(clear_json, (bytes, bytearray)):
        obj = json.loads(clear_json.decode("utf-8"))
    elif isinstance(clear_json, str):
        obj = json.loads(clear_json)
    else:
        obj = clear_json

    schema = load_device_schema(data_dir, schema_id)
    if schema is None:
        if require_schema_file and schema_id != "default":
            raise SchemaError(f"schema not registered: {schema_id}", reason="missing")
        schema = dict(DEFAULT_SCHEMA)
        schema["schema_id"] = schema_id
    validate_payload(obj, schema, device_id=device_id)
