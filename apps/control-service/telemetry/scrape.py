"""Render Prometheus scrape configs from templates (GATEWAY_IP, cAdvisor :8080)."""

from __future__ import annotations

from pathlib import Path
from typing import Mapping

# Bundled fallback matching deploy/templates/prometheus.yml (PR1).
_DEFAULT_TEMPLATE = """# Generated — do not edit by hand
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'node'
    scrape_interval: 5s
    static_configs:
      - targets: ['{{GATEWAY_IP}}:9100']
        labels:
          instance: 'gateway'

  - job_name: 'cadvisor'
    static_configs:
      - targets: ['{{GATEWAY_IP}}:{{CADVISOR_PORT}}']
        labels:
          instance: 'gateway'

  - job_name: 'node-exporter-textfile'
    static_configs:
      - targets: ['{{GATEWAY_IP}}:9100']
    metric_relabel_configs:
      - source_labels: [__name__]
        regex: 'mqtt_connected_sensor.*'
        action: keep
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
        # Prefer repo deploy/templates when running from a checkout.
        repo_tmpl = (
            Path(__file__).resolve().parents[3]
            / "deploy"
            / "templates"
            / "prometheus.yml"
        )
        if repo_tmpl.is_file():
            text = repo_tmpl.read_text(encoding="utf-8")
            # PR1 template hard-codes :8080; normalize to placeholder if absent.
            if "{{CADVISOR_PORT}}" not in text and ":8080" in text:
                text = text.replace("{{GATEWAY_IP}}:8080", "{{GATEWAY_IP}}:{{CADVISOR_PORT}}")
            return text
        return _DEFAULT_TEMPLATE
    path = Path(template)
    if path.is_file():
        return path.read_text(encoding="utf-8")
    return str(template)


def render_prometheus_scrape(
    gateway_ip: str,
    *,
    cadvisor_port: int | str = 8080,
    template: str | Path | None = None,
    extra_values: Mapping[str, str] | None = None,
) -> str:
    """Render prometheus.yml scrape targets for the gateway."""
    gateway_ip = gateway_ip.strip()
    if not gateway_ip:
        raise ValueError("gateway_ip is required")
    values: dict[str, str] = {
        "GATEWAY_IP": gateway_ip,
        "CADVISOR_PORT": str(cadvisor_port),
    }
    if extra_values:
        values.update({k: str(v) for k, v in extra_values.items()})
    return render_text(_resolve_template(template), values)
