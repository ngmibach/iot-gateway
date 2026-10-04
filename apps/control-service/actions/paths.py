"""Gateway install-root path helpers."""

from __future__ import annotations

from dataclasses import dataclass


DEFAULT_INSTALL_ROOT = "/opt/iot-gateway"
HAPROXY_CONTAINER = "iot-haproxy"
RESERVED_USERNAMES = frozenset({"nodered", "anonymous"})


@dataclass(frozen=True)
class GatewayPaths:
    install_root: str = DEFAULT_INSTALL_ROOT

    @property
    def compose_file(self) -> str:
        return f"{self.install_root}/docker-compose.yaml"

    @property
    def acl(self) -> str:
        return f"{self.install_root}/mosquitto/config/acl"

    @property
    def passwords(self) -> str:
        return f"{self.install_root}/mosquitto/config/passwords"

    @property
    def allowed_ips(self) -> str:
        return f"{self.install_root}/haproxy/allowed-ips.txt"

    @property
    def ca_crt(self) -> str:
        return f"{self.install_root}/certs/ca.crt"

    @property
    def ca_key(self) -> str:
        return f"{self.install_root}/certs/ca.key"

    @property
    def mosquitto_log(self) -> str:
        return f"{self.install_root}/mosquitto/log/mosquitto.log"

    @property
    def nodered_log(self) -> str:
        return f"{self.install_root}/nodered/data/logs/sensor_data.log"

    @property
    def haproxy_log(self) -> str:
        return f"{self.install_root}/haproxy/logs/haproxy.log"

    @property
    def gateway_state_log(self) -> str:
        return f"{self.install_root}/logs/gateway-state.log"

    @property
    def ids_alerts_log(self) -> str:
        return f"{self.install_root}/logs/ids-alerts.log"

    def log_paths(self) -> tuple[str, ...]:
        return (
            self.mosquitto_log,
            self.nodered_log,
            self.haproxy_log,
            self.gateway_state_log,
            self.ids_alerts_log,
        )
