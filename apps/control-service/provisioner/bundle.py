"""Local staging: copy gateway tree, render Promtail, prepare upload."""

from __future__ import annotations

import importlib.util
import shutil
import sys
from pathlib import Path
from typing import Mapping

# Skip bulky / generated paths when packing the gateway bundle.
EXCLUDE_DIR_NAMES = {
    "__pycache__",
    ".git",
    "node_modules",
    ".venv",
    "venv",
}
EXCLUDE_SUFFIXES = {".pyc", ".pyo"}

PROMTAIL_REL = Path("promtail") / "config" / "promtail-config.yaml"
FORBIDDEN_PROMTAIL_MARKERS = ("172.17.0.1", "{{")


def repo_root_from_here() -> Path:
    # provisioner/ -> control-service/ -> apps/ -> repo
    return Path(__file__).resolve().parents[3]


def load_render_config(repo_root: Path | None = None):
    """Import tools/render_config.py without requiring an installed package."""
    root = repo_root or repo_root_from_here()
    path = root / "tools" / "render_config.py"
    if not path.is_file():
        raise FileNotFoundError(f"render_config not found: {path}")
    spec = importlib.util.spec_from_file_location("iotgw_render_config", path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load {path}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def should_exclude(path: Path, root: Path) -> bool:
    rel_parts = path.relative_to(root).parts
    if any(part in EXCLUDE_DIR_NAMES for part in rel_parts):
        return True
    if path.suffix in EXCLUDE_SUFFIXES:
        return True
    return False


def stage_gateway_bundle(
    gateway_src: Path,
    staging_dir: Path,
    *,
    values: Mapping[str, str],
    template_dir: Path | None = None,
    repo_root: Path | None = None,
) -> Path:
    """Copy gateway_src → staging_dir and render Promtail onto the destination path.

    Fails closed if the Promtail template is missing or the rendered file still
    contains ``172.17.0.1`` / unresolved ``{{`` placeholders.
    """
    gateway_src = Path(gateway_src).resolve()
    staging_dir = Path(staging_dir).resolve()
    if not gateway_src.is_dir():
        raise FileNotFoundError(f"gateway source not found: {gateway_src}")
    if staging_dir.exists():
        shutil.rmtree(staging_dir)
    staging_dir.mkdir(parents=True)

    for src in gateway_src.rglob("*"):
        if should_exclude(src, gateway_src):
            continue
        rel = src.relative_to(gateway_src)
        dest = staging_dir / rel
        if src.is_dir():
            dest.mkdir(parents=True, exist_ok=True)
            continue
        if not src.is_file():
            continue
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dest)

    root = repo_root or repo_root_from_here()
    tpl_dir = Path(template_dir) if template_dir else root / "deploy" / "templates"
    render = load_render_config(root)
    required = ("GATEWAY_IP", "MONITORING_IP")
    missing = [k for k in required if not str(values.get(k, "")).strip()]
    if missing:
        raise KeyError(f"missing template values: {', '.join(missing)}")

    monitoring_ip = str(values["MONITORING_IP"]).strip()
    promtail_tpl = tpl_dir / "promtail-config.yaml"
    if not promtail_tpl.is_file():
        raise FileNotFoundError(
            f"Promtail template required for provision: {promtail_tpl}"
        )

    dest = staging_dir / PROMTAIL_REL
    dest.parent.mkdir(parents=True, exist_ok=True)
    text = render.render_text(promtail_tpl.read_text(encoding="utf-8"), dict(values))
    _assert_safe_promtail(text, monitoring_ip)
    dest.write_text(text, encoding="utf-8")
    return staging_dir


def _assert_safe_promtail(text: str, monitoring_ip: str) -> None:
    for marker in FORBIDDEN_PROMTAIL_MARKERS:
        if marker in text:
            raise ValueError(
                f"rendered Promtail config still contains {marker!r}; "
                "refusing to ship a mis-rendered Loki client URL"
            )
    expected = f"http://{monitoring_ip}:3100/loki/api/v1/push"
    if expected not in text:
        raise ValueError(
            f"rendered Promtail config missing expected Loki URL {expected!r}"
        )
