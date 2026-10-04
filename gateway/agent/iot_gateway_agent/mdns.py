"""Optional mDNS advertisement for _iot-gateway._tcp."""

from __future__ import annotations

import logging
import socket
from typing import Any

from . import AGENT_PORT, HEALTH_PATH, MQTT_TLS_PORT, SERVICE_TYPE, __version__

logger = logging.getLogger(__name__)


def _txt_records() -> dict[str, str]:
    return {
        "path": HEALTH_PATH,
        "ver": __version__,
        "mqtts": str(MQTT_TLS_PORT),
        "agent": str(AGENT_PORT),
    }


def start_mdns(port: int = AGENT_PORT) -> tuple[Any | None, bool]:
    """Register the service. Returns (zeroconf_or_info, enabled).

    If zeroconf is missing or registration fails, returns (None, False) and
    logs — HTTP continues without mDNS.
    """
    try:
        from zeroconf import ServiceInfo, Zeroconf
    except ImportError:
        logger.warning("zeroconf not installed; mDNS advertising disabled")
        return None, False

    hostname = socket.gethostname()
    try:
        # Prefer a non-loopback IPv4 for the advertisement
        addrs = socket.getaddrinfo(hostname, None, socket.AF_INET)
        ipv4 = next(
            (a[4][0] for a in addrs if not a[4][0].startswith("127.")),
            "127.0.0.1",
        )
    except OSError:
        ipv4 = "127.0.0.1"

    service_name = f"{hostname}.{SERVICE_TYPE}"
    info = ServiceInfo(
        SERVICE_TYPE,
        service_name,
        addresses=[socket.inet_aton(ipv4)],
        port=port,
        properties=_txt_records(),
        server=f"{hostname}.local.",
    )

    try:
        zc = Zeroconf()
        zc.register_service(info)
    except Exception as exc:  # noqa: BLE001 — never fail the agent for mDNS
        logger.warning("mDNS registration failed (%s); continuing without it", exc)
        return None, False

    logger.info(
        "mDNS advertising %s on %s:%s txt=%s",
        service_name,
        ipv4,
        port,
        _txt_records(),
    )
    return (zc, info), True


def stop_mdns(handle: Any | None) -> None:
    if handle is None:
        return
    try:
        zc, info = handle
        zc.unregister_service(info)
        zc.close()
    except Exception as exc:  # noqa: BLE001
        logger.debug("mDNS teardown: %s", exc)
