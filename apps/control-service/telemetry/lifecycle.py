"""Shared telemetry backend status snapshot (used by native lifecycle)."""

from __future__ import annotations

from dataclasses import dataclass

from .readiness import ProbeResult


@dataclass
class BackendStatus:
    """Backend lifecycle snapshot.

    ``running`` when probes are present means Loki+Prometheus readiness probes
    succeeded, and Grafana as well when Grafana is part of the installed stack.
    ``compose_ps`` is a free-form process/status blob (legacy field name kept for
    callers; native backends fill it with a short label such as ``native``).
    """

    running: bool
    compose_ps: str
    loki: ProbeResult | None = None
    prometheus: ProbeResult | None = None
    grafana: ProbeResult | None = None
    detail: str = ""
