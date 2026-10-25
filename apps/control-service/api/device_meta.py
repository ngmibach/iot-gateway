"""Helpers for devices.meta_json (kafka + fake-sensor flags)."""

from __future__ import annotations

import json
from typing import Any, Optional


def parse_meta(value: Any) -> dict[str, Any]:
    """Parse a registry ``meta_json`` column into a dict."""
    if value is None:
        return {}
    if isinstance(value, dict):
        return dict(value)
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError:
            return {}
        return dict(parsed) if isinstance(parsed, dict) else {}
    return {}


def is_fake_meta(meta: dict[str, Any] | None) -> bool:
    """True when meta marks the device as a fake/test sensor."""
    if not meta:
        return False
    return meta.get("is_fake") is True


def fake_block(meta: dict[str, Any] | None) -> dict[str, Any] | None:
    """Return the nested ``fake`` object when present and a dict."""
    if not meta:
        return None
    block = meta.get("fake")
    return dict(block) if isinstance(block, dict) else None


def merge_device_meta(
    existing: Any = None,
    *,
    kafka_topic: Optional[str] = None,
    kafka_retention_bytes: Any = None,
    is_fake: Optional[bool] = None,
    fake: Optional[dict[str, Any]] = None,
    clear_fake: bool = False,
) -> dict[str, Any]:
    """Merge kafka / fake fields into device meta.

    ``clear_fake=True`` drops ``is_fake`` / ``fake`` (real-sensor register path).
    Passing ``is_fake`` / ``fake`` updates those keys. Nested ``fake`` is shallow-merged.
    """
    meta = parse_meta(existing)
    if kafka_topic is not None:
        meta["kafka_topic"] = kafka_topic
    if kafka_retention_bytes is not None:
        meta["kafka_retention_bytes"] = kafka_retention_bytes
    if clear_fake:
        meta.pop("is_fake", None)
        meta.pop("fake", None)
        return meta
    if is_fake is not None:
        meta["is_fake"] = bool(is_fake)
        if not is_fake:
            meta.pop("fake", None)
    if fake is not None:
        prev = fake_block(meta) or {}
        merged = {**prev, **fake}
        meta["fake"] = merged
        meta["is_fake"] = True
    return meta
