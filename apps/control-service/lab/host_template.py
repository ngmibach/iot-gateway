"""Template HOST= in fake_sensor scripts to the gateway IP (lab staging only)."""

from __future__ import annotations

import re
import shutil
from pathlib import Path

# Matches HOST="…" / HOST='…' / HOST=… and {{GATEWAY_IP}} placeholders.
HOST_LINE_RE = re.compile(
    r'^(HOST\s*=\s*)(?:\{\{GATEWAY_IP\}\}|["\']?[^"\'\n]*["\']?)(.*)$',
    re.MULTILINE,
)


def apply_host_to_script(text: str, gateway_ip: str) -> str:
    """Rewrite HOST= lines to ``HOST="<gateway_ip>"``."""
    ip = gateway_ip.strip()
    if not ip:
        raise ValueError("gateway_ip required")

    def _sub(m: re.Match[str]) -> str:
        return f'{m.group(1)}"{ip}"{m.group(2)}'

    out, n = HOST_LINE_RE.subn(_sub, text)
    if n == 0 and "HOST=" not in text and "{{GATEWAY_IP}}" not in text:
        # No HOST line — leave unchanged (non-sensor scripts).
        return text
    return out


def template_host_in_tree(root: Path | str, gateway_ip: str) -> list[Path]:
    """Rewrite HOST in every ``test_sensor_data.sh`` under ``root``. Returns touched paths."""
    root = Path(root)
    touched: list[Path] = []
    for script in sorted(root.rglob("test_sensor_data.sh")):
        original = script.read_text(encoding="utf-8")
        updated = apply_host_to_script(original, gateway_ip)
        if updated != original:
            script.write_text(updated, encoding="utf-8")
            touched.append(script)
        elif f'HOST="{gateway_ip.strip()}"' in original:
            touched.append(script)
    return touched


def stage_fake_sensor_tree(
    source: Path | str,
    dest: Path | str,
    *,
    gateway_ip: str,
) -> Path:
    """Copy ``fake_sensor/`` into ``dest`` and template HOST. Returns dest path."""
    source = Path(source).resolve()
    dest = Path(dest)
    if not source.is_dir():
        raise FileNotFoundError(f"fake_sensor source missing: {source}")
    if dest.exists():
        shutil.rmtree(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(
        source,
        dest,
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc", ".git"),
    )
    template_host_in_tree(dest, gateway_ip)
    return dest
