from __future__ import annotations

from typing import Any


def safe_float(value: Any, default: float = 0.0) -> float:
    try:
        if value is None:
            return default
        return float(value)
    except (TypeError, ValueError):
        return default


def device_id_from_topic(topic: str) -> str:
    if not topic:
        return ""
    parts = topic.split("/")
    if len(parts) >= 3 and parts[0] == "sensors":
        return parts[1]
    return ""