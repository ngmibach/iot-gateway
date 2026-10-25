"""Unit tests for compact schema_validate."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from iot_gateway_agent.schema_validate import SchemaError, load_schema, validate_payload

SCHEMA = {
    "schema_id": "temp-v1",
    "type": "object",
    "additionalProperties": False,
    "required": ["device_id", "ts_ms", "temp_c"],
    "properties": {
        "device_id": {"type": "string", "const": "@device_id"},
        "ts_ms": {"type": "integer", "minimum": 0},
        "temp_c": {"type": "number"},
        "ok": {"type": "boolean"},
    },
}


class SchemaValidateTests(unittest.TestCase):
    def test_happy_path(self) -> None:
        validate_payload(
            {"device_id": "dev-1", "ts_ms": 10, "temp_c": 22.5, "ok": True},
            SCHEMA,
            device_id="dev-1",
        )

    def test_wrong_type(self) -> None:
        with self.assertRaises(SchemaError):
            validate_payload(
                {"device_id": "dev-1", "ts_ms": "nope", "temp_c": 1},
                SCHEMA,
                device_id="dev-1",
            )

    def test_missing_field(self) -> None:
        with self.assertRaises(SchemaError):
            validate_payload(
                {"device_id": "dev-1", "ts_ms": 1},
                SCHEMA,
                device_id="dev-1",
            )

    def test_extra_field(self) -> None:
        with self.assertRaises(SchemaError):
            validate_payload(
                {
                    "device_id": "dev-1",
                    "ts_ms": 1,
                    "temp_c": 1.0,
                    "extra": True,
                },
                SCHEMA,
                device_id="dev-1",
            )

    def test_device_id_const(self) -> None:
        with self.assertRaises(SchemaError):
            validate_payload(
                {"device_id": "other", "ts_ms": 1, "temp_c": 1.0},
                SCHEMA,
                device_id="dev-1",
            )

    def test_load_schema(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "s.json"
            path.write_text(json.dumps(SCHEMA), encoding="utf-8")
            loaded = load_schema(path)
            self.assertEqual(loaded["schema_id"], "temp-v1")


if __name__ == "__main__":
    unittest.main()
