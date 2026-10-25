"""Compact JSON Schema subset validator (no jsonschema dependency)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class SchemaError(ValueError):
    """Payload failed schema validation."""

    reason: str = "schema"

    def __init__(self, message: str, *, reason: str | None = None) -> None:
        super().__init__(message)
        if reason is not None:
            self.reason = reason


_TYPE_MAP = {
    "object": dict,
    "array": list,
    "string": str,
    "integer": int,
    "number": (int, float),
    "boolean": bool,
}


def load_schema(path: str | Path) -> dict:
    """Load a schema JSON file from disk."""
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise SchemaError("schema root must be an object")
    return data


def validate_payload(
    data: Any,
    schema: dict,
    *,
    device_id: str | None = None,
) -> None:
    """Validate ``data`` against a compact schema subset; raise SchemaError."""
    _validate(data, schema, path="$", device_id=device_id)


def _validate(
    data: Any,
    schema: dict,
    *,
    path: str,
    device_id: str | None,
) -> None:
    if "type" in schema:
        expected = schema["type"]
        if expected not in _TYPE_MAP:
            raise SchemaError(f"{path}: unsupported type {expected!r}")
        py_types = _TYPE_MAP[expected]
        # bool is a subclass of int — reject bool for integer/number
        if expected in ("integer", "number") and isinstance(data, bool):
            raise SchemaError(f"{path}: expected {expected}, got boolean")
        if expected == "number":
            if not isinstance(data, (int, float)) or isinstance(data, bool):
                raise SchemaError(f"{path}: expected number, got {type(data).__name__}")
        elif expected == "integer":
            if not isinstance(data, int) or isinstance(data, bool):
                raise SchemaError(f"{path}: expected integer, got {type(data).__name__}")
        elif not isinstance(data, py_types):
            raise SchemaError(
                f"{path}: expected {expected}, got {type(data).__name__}"
            )

    if "const" in schema:
        const_val = schema["const"]
        if const_val == "@device_id":
            if device_id is None:
                raise SchemaError(f"{path}: @device_id const requires device_id")
            if data != device_id:
                raise SchemaError(
                    f"{path}: expected device_id {device_id!r}, got {data!r}"
                )
        elif data != const_val:
            raise SchemaError(f"{path}: expected const {const_val!r}, got {data!r}")

    if isinstance(data, str):
        if "minLength" in schema and len(data) < schema["minLength"]:
            raise SchemaError(f"{path}: string shorter than minLength")
        if "maxLength" in schema and len(data) > schema["maxLength"]:
            raise SchemaError(f"{path}: string longer than maxLength")

    if isinstance(data, (int, float)) and not isinstance(data, bool):
        if "minimum" in schema and data < schema["minimum"]:
            raise SchemaError(f"{path}: value below minimum")
        if "maximum" in schema and data > schema["maximum"]:
            raise SchemaError(f"{path}: value above maximum")

    if isinstance(data, dict) and (
        "properties" in schema or "required" in schema or "additionalProperties" in schema
    ):
        props = schema.get("properties") or {}
        required = schema.get("required") or []
        for key in required:
            if key not in data:
                raise SchemaError(f"{path}: missing required field {key!r}")
        for key, value in data.items():
            if key in props:
                _validate(
                    value,
                    props[key],
                    path=f"{path}.{key}",
                    device_id=device_id,
                )
            elif schema.get("additionalProperties", True) is False:
                raise SchemaError(f"{path}: unexpected field {key!r}")

    if isinstance(data, list) and "items" in schema:
        item_schema = schema["items"]
        for i, item in enumerate(data):
            _validate(
                item,
                item_schema,
                path=f"{path}[{i}]",
                device_id=device_id,
            )
