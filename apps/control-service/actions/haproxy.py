"""HAProxy reload: HUP PID 1, else compose restart (never down -v)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from .paths import HAPROXY_CONTAINER, GatewayPaths
from .shellutil import shell_quote

if TYPE_CHECKING:
    from .ssh import SSHClient


def reload_haproxy(
    ssh: "SSHClient",
    paths: GatewayPaths,
    *,
    container_name: str = HAPROXY_CONTAINER,
) -> str:
    """Signal HAProxy master (PID 1 after entrypoint fix). Fallback: restart.

    Returns ``"hup"`` or ``"restart"`` indicating which path succeeded.
    """
    hup = ssh.run(f"docker kill -s HUP {shell_quote(container_name)}")
    if hup.exit_code == 0:
        return "hup"
    restart = ssh.run(
        "docker compose"
        f" -f {shell_quote(paths.compose_file)}"
        " restart haproxy"
    )
    restart.check()
    return "restart"


def restart_mosquitto(ssh: "SSHClient", paths: GatewayPaths) -> None:
    ssh.run(
        "docker compose"
        f" -f {shell_quote(paths.compose_file)}"
        " restart mosquitto"
    ).check()
