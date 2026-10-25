"""Gateway install-root and agent data-dir path helpers."""

from __future__ import annotations

from dataclasses import dataclass


DEFAULT_INSTALL_ROOT = "/opt/iot-gateway-agent"
DEFAULT_AGENT_DATA = "/var/lib/iot-gateway-agent"
RESERVED_USERNAMES = frozenset({"nodered", "anonymous"})


@dataclass(frozen=True)
class GatewayPaths:
    """Paths for the packaged agent layout (system Mosquitto, no Docker/HAProxy)."""

    install_root: str = DEFAULT_INSTALL_ROOT
    data_dir: str = DEFAULT_AGENT_DATA

    @property
    def acl(self) -> str:
        return f"{self.data_dir}/mosquitto/acl"

    @property
    def passwords(self) -> str:
        return f"{self.data_dir}/mosquitto/passwords"

    @property
    def certs_dir(self) -> str:
        return f"{self.data_dir}/certs"

    @property
    def ca_crt(self) -> str:
        return f"{self.data_dir}/certs/ca.crt"

    @property
    def ca_key(self) -> str:
        return f"{self.data_dir}/certs/ca.key"

    @property
    def server_crt(self) -> str:
        return f"{self.data_dir}/certs/server.crt"

    @property
    def server_key(self) -> str:
        return f"{self.data_dir}/certs/server.key"

    @property
    def server_pem(self) -> str:
        return f"{self.data_dir}/certs/server.pem"

    @property
    def decrypt_crt(self) -> str:
        """Client cert for the agent decrypt worker (mTLS to local Mosquitto)."""
        return f"{self.data_dir}/certs/decrypt.crt"

    @property
    def decrypt_key(self) -> str:
        return f"{self.data_dir}/certs/decrypt.key"

    @property
    def mosquitto_log(self) -> str:
        return f"{self.data_dir}/mosquitto/log/mosquitto.log"

    @property
    def sensor_data_log(self) -> str:
        return f"{self.data_dir}/logs/sensor_data.log"

    @property
    def kafka_dir(self) -> str:
        return f"{self.data_dir}/kafka"

    @property
    def kafka_topics_catalog(self) -> str:
        """Logical per-sensor Kafka topic catalog (retention.bytes caps)."""
        return f"{self.data_dir}/kafka/topics.json"

    def log_paths(self) -> tuple[str, ...]:
        return (self.mosquitto_log, self.sensor_data_log)
