"""System Mosquitto reload/restart via systemd (no Docker)."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .ssh import SSHClient


def reload_mosquitto(ssh: "SSHClient") -> str:
    """Prefer ``systemctl reload``; fall back to ``restart``.

    Returns ``"reload"`` or ``"restart"`` indicating which path succeeded.
    """
    reloaded = ssh.run("systemctl reload mosquitto")
    if reloaded.exit_code == 0:
        return "reload"
    ssh.run("systemctl restart mosquitto").check()
    return "restart"


def restart_mosquitto(ssh: "SSHClient") -> None:
    """Force a full Mosquitto service restart."""
    ssh.run("systemctl restart mosquitto").check()
