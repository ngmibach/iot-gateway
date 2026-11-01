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
    schema_id: Optional[str] = None,
    crypto_profile: Optional[str] = None,
    publish_blocked: Optional[bool] = None,
    topics_rw_before_block: Any = None,
    clear_publish_block: bool = False,
    auto_prevent: Optional[dict[str, Any]] = None,
    clear_auto_prevent: bool = False,
) -> dict[str, Any]:
    """Merge kafka / fake / crypto / control fields into device meta.

    ``clear_fake=True`` drops ``is_fake`` / ``fake`` (real-sensor register path).
    Passing ``is_fake`` / ``fake`` updates those keys. Nested ``fake`` is shallow-merged.
    ``clear_publish_block=True`` drops Control-tab block flags.
    ``auto_prevent`` replaces/merges the Auto prevent policy block.
    """
    meta = parse_meta(existing)
    if kafka_topic is not None:
        meta["kafka_topic"] = kafka_topic
    if kafka_retention_bytes is not None:
        meta["kafka_retention_bytes"] = kafka_retention_bytes
    if schema_id is not None:
        meta["schema_id"] = schema_id
    if crypto_profile is not None:
        meta["crypto_profile"] = crypto_profile
    if clear_publish_block:
        meta.pop("publish_blocked", None)
        meta.pop("topics_rw_before_block", None)
    elif publish_blocked is not None:
        meta["publish_blocked"] = bool(publish_blocked)
        if topics_rw_before_block is not None:
            meta["topics_rw_before_block"] = topics_rw_before_block
        if not publish_blocked:
            meta.pop("topics_rw_before_block", None)
    if clear_auto_prevent:
        meta.pop("auto_prevent", None)
    elif auto_prevent is not None:
        clear_trip = bool(auto_prevent.get("clear_trip"))
        meta["auto_prevent"] = normalize_auto_prevent(
            auto_prevent_block(meta),
            enabled=auto_prevent["enabled"] if "enabled" in auto_prevent else None,
            limit=auto_prevent["limit"] if "limit" in auto_prevent else None,
            window_s=auto_prevent["window_s"] if "window_s" in auto_prevent else None,
            tripped_at=auto_prevent.get("tripped_at")
            if ("tripped_at" in auto_prevent and not clear_trip)
            else None,
            quarantine_ip=auto_prevent.get("quarantine_ip")
            if ("quarantine_ip" in auto_prevent and not clear_trip)
            else None,
            clear_trip=clear_trip,
        )
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


def is_publish_blocked_meta(meta: dict[str, Any] | None) -> bool:
    """True when Control tab has blocked MQTT publish for this device."""
    if not meta:
        return False
    return meta.get("publish_blocked") is True


DEFAULT_AUTO_PREVENT_LIMIT = 10
DEFAULT_AUTO_PREVENT_WINDOW_S = 300


def auto_prevent_block(meta: dict[str, Any] | None) -> dict[str, Any] | None:
    """Return the nested ``auto_prevent`` object when present and a dict."""
    if not meta:
        return None
    block = meta.get("auto_prevent")
    return dict(block) if isinstance(block, dict) else None


def normalize_auto_prevent(
    value: Any = None,
    *,
    enabled: Optional[bool] = None,
    limit: Optional[int] = None,
    window_s: Optional[int] = None,
    tripped_at: Any = None,
    quarantine_ip: Any = None,
    clear_trip: bool = False,
) -> dict[str, Any]:
    """Build a normalized ``auto_prevent`` meta block."""
    base = dict(value) if isinstance(value, dict) else {}
    out: dict[str, Any] = {
        "enabled": bool(base.get("enabled", False)),
        "limit": int(base.get("limit") or DEFAULT_AUTO_PREVENT_LIMIT),
        "window_s": int(base.get("window_s") or DEFAULT_AUTO_PREVENT_WINDOW_S),
    }
    if base.get("tripped_at") is not None:
        out["tripped_at"] = base.get("tripped_at")
    if base.get("quarantine_ip"):
        out["quarantine_ip"] = str(base.get("quarantine_ip")).strip()
    if enabled is not None:
        out["enabled"] = bool(enabled)
    if limit is not None:
        out["limit"] = int(limit)
    if window_s is not None:
        out["window_s"] = int(window_s)
    if clear_trip:
        out.pop("tripped_at", None)
        out.pop("quarantine_ip", None)
    else:
        if tripped_at is not None:
            out["tripped_at"] = tripped_at
        if quarantine_ip is not None:
            ip = str(quarantine_ip).strip()
            if ip:
                out["quarantine_ip"] = ip
            else:
                out.pop("quarantine_ip", None)
    # Keep sane bounds for agent enforcement.
    out["limit"] = max(1, min(int(out["limit"]), 100000))
    out["window_s"] = max(60, min(int(out["window_s"]), 86400))
    return out


def is_auto_prevent_enabled_meta(meta: dict[str, Any] | None) -> bool:
    block = auto_prevent_block(meta)
    return bool(block and block.get("enabled") is True)


def is_auto_prevent_quarantined_meta(meta: dict[str, Any] | None) -> bool:
    block = auto_prevent_block(meta)
    if not block:
        return False
    return bool(block.get("tripped_at") or block.get("quarantine_ip"))
