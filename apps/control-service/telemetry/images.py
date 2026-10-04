"""Image set manifest for monitoring backends (and documented gateway refs)."""

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
# Tags are :latest until field-kit digest pinning ships with image-cache work.
IMAGE_SET: dict[str, Any] = _load()


def required_images(*, include_optional_grafana: bool = False) -> list[str]:
    """Return pull/load image refs for app-managed backends (+ optional Grafana)."""
    data = _load()
    out = list(data.get("monitoring", []))
    if include_optional_grafana:
        out.extend(data.get("optional_monitoring", []))
    return out
