"""Shared telemetry backend status snapshot (used by native lifecycle)."""

from __future__ import annotations

from dataclasses import dataclass

from .readiness import ProbeResult


@dataclass
class BackendStatus:
    """Backend lifecycle snapshot.

    ``running`` when probes are present means both readiness probes succeeded.
    ``compose_ps`` is a free-form process/status blob (legacy field name kept for
    callers; native backends fill it with a short label such as ``native``).
    """

    running: bool
    compose_ps: str
    loki: ProbeResult | None = None
    prometheus: ProbeResult | None = None
    detail: str = ""
