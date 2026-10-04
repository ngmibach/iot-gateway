"""Build /v1/health and /v1/info payloads (liveness only)."""

from __future__ import annotations

import socket
from typing import Any

from . import AGENT_PORT, HEALTH_PATH, MQTT_TLS_PORT, __version__


def _hostname() -> str:
    try:
        return socket.gethostname()
    except OSError:
        return "unknown"


def build_health(*, mdns_enabled: bool, port: int = AGENT_PORT) -> dict[str, Any]:
    """Agent liveness. Stack degraded/healthy comes from SSH compose-ps / Prometheus."""
    return {
        "status": "ok",
        "agent": "iot-gateway-agent",
        "version": __version__,
        "hostname": _hostname(),
        "mdns": bool(mdns_enabled),
        "port": port,
    }


def build_info(*, port: int = AGENT_PORT) -> dict[str, Any]:
    return {
        "service": "iot-gateway-agent",
        "version": __version__,
        "hostname": _hostname(),
        "port": port,
        "mqtts": MQTT_TLS_PORT,
        "path": HEALTH_PATH,
        "api": ["GET /v1/health", "GET /v1/info"],
        "read_only": True,
    }
