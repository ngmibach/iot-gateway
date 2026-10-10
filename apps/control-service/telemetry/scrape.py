"""Render Prometheus scrape configs from templates (GATEWAY_IP, cAdvisor :8080)."""

from __future__ import annotations

from pathlib import Path
from typing import Mapping

# K11: cAdvisor port is pinned at 8080 on the gateway; do not re-parameterize here.
_DEFAULT_TEMPLATE = """# Generated — do not edit by hand
# Default path scrapes the monolithic gateway agent (no Docker / no cAdvisor).
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'iot-gateway-agent'
    scrape_interval: 5s
    metrics_path: /metrics
    static_configs:
      - targets: ['{{GATEWAY_IP}}:9139']
        labels:
          instance: 'gateway'
"""


def _remaining_placeholders(text: str) -> list[str]:
    found: set[str] = set()
    start = 0
    while True:
        i = text.find("{{", start)
        if i < 0:
            break
        j = text.find("}}", i + 2)
        if j < 0:
            break
        found.add(text[i + 2 : j].strip())
        start = j + 2
    return sorted(found)


def render_text(template: str, values: Mapping[str, str]) -> str:
    out = template
    for key, val in values.items():
        out = out.replace("{{" + key + "}}", val)
    leftover = _remaining_placeholders(out)
    if leftover:
        raise KeyError(f"missing template values: {', '.join(leftover)}")
    return out


def _resolve_template(template: str | Path | None) -> str:
    if template is None:
        repo_tmpl = (
            Path(__file__).resolve().parents[3]
            / "deploy"
            / "templates"
            / "prometheus.yml"
        )
        if repo_tmpl.is_file():
            return repo_tmpl.read_text(encoding="utf-8")
        return _DEFAULT_TEMPLATE
    path = Path(template)
    if path.is_file():
        return path.read_text(encoding="utf-8")
    return str(template)


def render_prometheus_scrape(
    gateway_ip: str,
    *,
    template: str | Path | None = None,
    extra_values: Mapping[str, str] | None = None,
) -> str:
    """Render prometheus.yml scrape targets (cAdvisor fixed at :8080 per K11)."""
    gateway_ip = gateway_ip.strip()
    if not gateway_ip:
        raise ValueError("gateway_ip is required")
    values: dict[str, str] = {"GATEWAY_IP": gateway_ip}
    if extra_values:
        values.update({k: str(v) for k, v in extra_values.items()})
    return render_text(_resolve_template(template), values)
