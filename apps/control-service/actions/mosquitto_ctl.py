"""System Mosquitto reload/restart via systemd (no Docker)."""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

from .shellutil import shell_quote

if TYPE_CHECKING:
    from .ssh import SSHClient


def _sudo_systemctl(
    ssh: "SSHClient",
    action: str,
    *,
    sudo_password: str | None = None,
    timeout: float = 60.0,
):
    """Run ``systemctl <action> mosquitto`` under sudo when needed."""
    inner = f"systemctl {action} mosquitto"
    quoted = shell_quote(inner)
    if sudo_password:
        return ssh.run(
            f"sudo -S -p '' -- sh -c {quoted}",
            timeout=timeout,
            stdin=sudo_password,
        )
    # Prefer passwordless sudo; fall back to bare systemctl (NOPASSWD / root).
    elevated = ssh.run(f"sudo -n -- sh -c {quoted}", timeout=timeout)
    if elevated.exit_code == 0:
        return elevated
    return ssh.run(inner, timeout=timeout)


def reload_mosquitto(
    ssh: "SSHClient",
    *,
    sudo_password: str | None = None,
) -> str:
    """Prefer ``systemctl reload``; fall back to ``restart``.

    Returns ``"reload"`` or ``"restart"`` indicating which path succeeded.
    Day-2 playbooks must pass ``sudo_password`` — plain ``systemctl`` fails with
    ``Interactive authentication required`` for the SSH login user.
    """
    reloaded = _sudo_systemctl(ssh, "reload", sudo_password=sudo_password)
    if reloaded.exit_code == 0:
        return "reload"
    _sudo_systemctl(ssh, "restart", sudo_password=sudo_password).check()
    return "restart"


def restart_mosquitto(
    ssh: "SSHClient",
    *,
    sudo_password: str | None = None,
) -> None:
    """Force a full Mosquitto service restart."""
    _sudo_systemctl(ssh, "restart", sudo_password=sudo_password).check()
