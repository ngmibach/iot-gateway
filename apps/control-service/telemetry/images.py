"""Image set manifest for monitoring backends and gateway field kits."""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

_MANIFEST = Path(__file__).resolve().parent / "image_set.json"


@lru_cache(maxsize=1)
def _load() -> dict[str, Any]:
    return json.loads(_MANIFEST.read_text(encoding="utf-8"))


def image_set() -> dict[str, Any]:
    """Return the parsed image_set.json manifest."""
    return _load()


# Eager constant for simple imports / manifests.
IMAGE_SET: dict[str, Any] = _load()


def required_images(*, include_optional_grafana: bool = False) -> list[str]:
    """Return pull/load image refs for app-managed backends (+ optional Grafana)."""
    data = _load()
    out = list(data.get("monitoring", []))
    if include_optional_grafana:
        out.extend(data.get("optional_monitoring", []))
    return out


def all_field_kit_images(*, include_optional_grafana: bool = False) -> list[str]:
    """Monitoring + prebuilt gateway images (excludes local build contexts)."""
    data = _load()
    out = list(data.get("monitoring", [])) + list(data.get("gateway", []))
    if include_optional_grafana:
        out.extend(data.get("optional_monitoring", []))
    seen: set[str] = set()
    unique: list[str] = []
    for img in out:
        if img not in seen:
            seen.add(img)
            unique.append(img)
    return unique
