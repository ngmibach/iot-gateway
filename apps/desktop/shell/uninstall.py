"""Selective uninstall: Gateway agent and/or full PC Monitoring app-data wipe."""

from __future__ import annotations

import logging
from typing import Any, Callable, Optional

from . import keyring_store, ssh_setup
from .paths import ensure_data_dir, load_settings, save_settings, wipe_app_data

logger = logging.getLogger(__name__)


class UninstallError(RuntimeError):
    """Operator-facing uninstall failure."""


def _gateway_provisioned(settings: dict[str, Any]) -> bool:
    host = str(settings.get("ssh_host") or settings.get("gateway_ip") or "").strip()
    return bool(host)


def clear_local_secrets(gateway_ids: list[str]) -> None:
    """Drop known keyring / fallback secrets for gateways + admin + signing."""
    for gid in gateway_ids:
        for kind in ("ssh", "admin", "signing"):
            try:
                keyring_store.delete_secret(gid, kind=kind)
            except Exception:  # noqa: BLE001
                logger.debug("keyring delete failed for %s/%s", gid, kind, exc_info=True)
    for account in ("local", "signing-pfx", "signing-gpg"):
        for kind in ("admin", "signing", "ssh"):
            try:
                keyring_store.delete_secret(account, kind=kind)
            except Exception:  # noqa: BLE001
                pass
    # Wipe fallback file entirely when present.
    try:
        path = keyring_store._fallback_path()
        if path.is_file():
            path.unlink(missing_ok=True)
    except OSError:
        pass


def uninstall_gateway_over_ssh(
    *,
    host: str,
    username: str,
    port: int,
    gateway_id: str,
    sudo_password: str,
    open_ssh: Optional[Callable[..., Any]] = None,
) -> list[str]:
    """SSH to the Pi and remove the monolithic agent (leave apt mosquitto)."""
    from provisioner.agent_install import (  # type: ignore[import-not-found]
        uninstall_monolithic_agent,
    )
    from provisioner.ssh import ParamikoSSHSession  # type: ignore[import-not-found]

    key_path = ssh_setup.key_paths_for(gateway_id).private
    if not key_path.is_file():
        raise UninstallError(
            "SSH private key missing — pin host key and install ed25519 before "
            "uninstalling the gateway, or remove the gateway registry row only."
        )
    session_factory = open_ssh or ParamikoSSHSession
    ssh = session_factory(
        host,
        username,
        key_filename=str(key_path),
        port=port,
    )
    try:
        return uninstall_monolithic_agent(ssh, sudo_password=sudo_password)
    finally:
        try:
            ssh.close()
        except Exception:  # noqa: BLE001
            pass


def remove_gateway_from_registry(gateway_id: str) -> bool:
    from registry.registry import Registry  # type: ignore[import-not-found]

    reg_path = ensure_data_dir() / "registry.sqlite"
    if not reg_path.is_file():
        return False
    reg = Registry(str(reg_path))
    try:
        return reg.delete_gateway(gateway_id)
    finally:
        reg.close()


def run_uninstall(
    *,
    gateway: bool,
    monitoring: bool,
    sudo_password: str = "",
    gateway_id: str | None = None,
    stop_telemetry: Callable[[], None],
    stop_services: Callable[[], None],
    telemetry_uninstall: Callable[[], dict[str, Any]],
    reset_telemetry_mgr: Callable[[], None] | None = None,
) -> dict[str, Any]:
    """Execute selective uninstall with Monitoring ⇒ Gateway coupling.

    ``monitoring=True`` requires ``gateway=True`` whenever a gateway looks
    provisioned (ssh_host / gateway_ip in settings). Full app-data wipe runs
    only for Monitoring.
    """
    if not gateway and not monitoring:
        raise UninstallError("Select Gateway and/or Monitoring to uninstall")

    settings = load_settings()
    gid = (
        gateway_id
        or str(settings.get("default_gateway_id") or "gateway")
    ).strip() or "gateway"
    provisioned = _gateway_provisioned(settings)

    if monitoring and not gateway and provisioned:
        raise UninstallError(
            "Monitoring uninstall requires Gateway uninstall when a gateway "
            "has been provisioned. Select Gateway as well (or uninstall Gateway first)."
        )

    result: dict[str, Any] = {
        "ok": True,
        "gateway": None,
        "monitoring": None,
        "app_data": None,
        "notes": [],
    }

    # ── Gateway (SSH) ─────────────────────────────────────────────────
    if gateway and provisioned:
        host = str(settings.get("ssh_host") or settings.get("gateway_ip") or "").strip()
        username = str(settings.get("ssh_user") or "ubuntu").strip()
        port = int(settings.get("ssh_port") or 22)
        if not (sudo_password or "").strip():
            raise UninstallError(
                "Gateway sudo password required to remove the agent on the Pi"
            )
        notes = uninstall_gateway_over_ssh(
            host=host,
            username=username,
            port=port,
            gateway_id=gid,
            sudo_password=sudo_password,
        )
        removed = remove_gateway_from_registry(gid)
        clear_local_secrets([gid])
        # Drop SSH-related settings but keep NIC / monitoring_ip until Monitoring wipe.
        for key in (
            "ssh_host",
            "ssh_user",
            "ssh_port",
            "provision_backend",
            "gateway_fingerprint",
        ):
            settings.pop(key, None)
        save_settings(settings)
        result["gateway"] = {
            "ok": True,
            "host": host,
            "notes": notes,
            "registry_removed": removed,
        }
        result["notes"].extend(notes)
    elif gateway and not provisioned:
        remove_gateway_from_registry(gid)
        result["gateway"] = {
            "ok": True,
            "skipped": True,
            "detail": "No provisioned gateway in settings — nothing to SSH-remove.",
        }
        result["notes"].append("Gateway: nothing provisioned locally")

    # ── Monitoring (+ full app-data wipe) ─────────────────────────────
    if monitoring:
        try:
            stop_services()
        except Exception as exc:  # noqa: BLE001
            logger.warning("stop_services during uninstall: %s", exc)
        try:
            stop_telemetry()
        except Exception as exc:  # noqa: BLE001
            logger.warning("stop_telemetry during uninstall: %s", exc)
        tel = telemetry_uninstall()
        if reset_telemetry_mgr is not None:
            reset_telemetry_mgr()
        # Clear secrets for any remaining known ids before wiping files.
        clear_local_secrets([gid, "gateway", "local"])
        wiped = wipe_app_data()
        result["monitoring"] = tel
        result["app_data"] = wiped
        result["notes"].append(
            f"Telemetry removed under {tel.get('root')}; "
            f"app data wipe removed={wiped.get('removed')} skipped={wiped.get('skipped')}"
        )
        if tel.get("errors") or wiped.get("errors"):
            result["ok"] = False

    return result
