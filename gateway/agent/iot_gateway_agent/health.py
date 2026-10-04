"""Build /v1/health and /v1/info payloads (best-effort docker summary)."""

from __future__ import annotations

import json
import logging
import os
import shutil
import socket
import subprocess
from typing import Any

from . import AGENT_PORT, HEALTH_PATH, MQTT_TLS_PORT, __version__

logger = logging.getLogger(__name__)

# Expected gateway compose services; missing/unhealthy ones mark degraded.
EXPECTED_SERVICES = (
    "iot-mosquitto",
    "iot-haproxy",
    "iot-nodered",
    "iot-ids",
)


def _hostname() -> str:
    try:
        return socket.gethostname()
    except OSError:
        return "unknown"


def _docker_compose_ps(install_root: str | None) -> list[dict[str, Any]] | None:
    """Return a summary of compose services, or None if docker is unavailable."""
    if shutil.which("docker") is None:
        return None

    cwd = install_root or os.environ.get("INSTALL_ROOT") or os.getcwd()
    cmd = ["docker", "compose", "ps", "--format", "json"]
    try:
        proc = subprocess.run(
            cmd,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        logger.debug("docker compose ps failed: %s", exc)
        return None

    if proc.returncode != 0:
        logger.debug("docker compose ps rc=%s: %s", proc.returncode, proc.stderr.strip())
        return None

    services: list[dict[str, Any]] = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            # Older compose may emit a single JSON array
            try:
                rows = json.loads(proc.stdout)
            except json.JSONDecodeError:
                return None
            if isinstance(rows, list):
                return [_summarize_compose_row(r) for r in rows if isinstance(r, dict)]
            return None
        if isinstance(row, dict):
            services.append(_summarize_compose_row(row))
    return services


def _summarize_compose_row(row: dict[str, Any]) -> dict[str, Any]:
    name = row.get("Name") or row.get("name") or row.get("Service") or "unknown"
    state = row.get("State") or row.get("state") or row.get("Status") or "unknown"
    health = row.get("Health") or row.get("health") or ""
    return {
        "name": str(name),
        "state": str(state).lower(),
        "health": str(health).lower() if health else "",
    }


def _status_from_services(services: list[dict[str, Any]] | None) -> str:
    if services is None:
        # No docker — agent itself is fine; report ok without stack insight.
        return "ok"
    if not services:
        return "degraded"

    by_name = {s["name"]: s for s in services}
    for expected in EXPECTED_SERVICES:
        svc = by_name.get(expected)
        if svc is None:
            # Also match by short service name substring
            svc = next((s for s in services if expected in s["name"] or s["name"].endswith(expected)), None)
        if svc is None:
            return "degraded"
        state = svc.get("state", "")
        health = svc.get("health", "")
        if state not in ("running", "up"):
            return "degraded"
        if health in ("unhealthy", "starting"):
            return "degraded"
    return "ok"


def build_health(*, mdns_enabled: bool, install_root: str | None = None) -> dict[str, Any]:
    services = _docker_compose_ps(install_root)
    status = _status_from_services(services)
    payload: dict[str, Any] = {
        "status": status,
        "agent": "iot-gateway-agent",
        "version": __version__,
        "hostname": _hostname(),
        "mdns": bool(mdns_enabled),
        "port": AGENT_PORT,
    }
    if services is not None:
        payload["services"] = services
    return payload


def build_info() -> dict[str, Any]:
    return {
        "service": "iot-gateway-agent",
        "version": __version__,
        "hostname": _hostname(),
        "port": AGENT_PORT,
        "mqtts": MQTT_TLS_PORT,
        "path": HEALTH_PATH,
        "api": ["GET /v1/health", "GET /v1/info"],
        "read_only": True,
    }
