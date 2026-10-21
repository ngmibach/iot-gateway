"""Write provisioned gateways into the local registry.sqlite.

Monitoring (Metrics / Activities) reads ``GET /api/v1/gateways`` from the
control-service registry. Settings.json alone is not enough.
"""

from __future__ import annotations

from typing import Any, Optional

from .paths import ensure_data_dir


DEFAULT_AGENT_ROOT = "/opt/iot-gateway-agent"
DEFAULT_AGENT_PORT = 9139


def upsert_local_gateway(
    *,
    gateway_id: str,
    host: str,
    ssh_user: str,
    fingerprint: str,
    install_root: str = DEFAULT_AGENT_ROOT,
    monitoring_ip: Optional[str] = None,
    agent_url: Optional[str] = None,
    password_auth_enabled: bool = False,
    status: str = "provisioned",
) -> dict[str, Any]:
    """Insert/update a gateway row. Returns the stored row."""
    from registry.registry import Registry  # type: ignore[import-not-found]

    gid = (gateway_id or "").strip() or "gateway"
    host_s = (host or "").strip()
    user_s = (ssh_user or "").strip() or "ubuntu"
    fp = (fingerprint or "").strip() or "unknown"
    if not host_s:
        raise ValueError("host required to register gateway")
    root = (install_root or "").strip() or DEFAULT_AGENT_ROOT
    url = (agent_url or "").strip() or f"http://{host_s}:{DEFAULT_AGENT_PORT}"

    reg_path = ensure_data_dir() / "registry.sqlite"
    reg = Registry(str(reg_path))
    try:
        return reg.upsert_gateway(
            gid,
            host=host_s,
            ssh_user=user_s,
            install_root=root,
            fingerprint=fp,
            agent_url=url,
            monitoring_ip=(monitoring_ip or None),
            password_auth_enabled=1 if password_auth_enabled else 0,
            status=status,
        )
    finally:
        reg.close()


def fingerprint_from_settings(settings: dict[str, Any], host: str, port: int = 22) -> str:
    """Prefer pinned SSH host-key fingerprint from wizard settings."""
    pins = settings.get("ssh_host_pins") or {}
    if not isinstance(pins, dict):
        return ""
    for key in (f"{host}:{int(port)}", host):
        pin = pins.get(key)
        if isinstance(pin, dict):
            fp = str(pin.get("fingerprint_sha256") or "").strip()
            if fp:
                return fp
    return ""
