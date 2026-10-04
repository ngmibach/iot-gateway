"""Control-service settings from env (settings.json wiring comes with desktop)."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


def _default_data_dir() -> Path:
    override = os.environ.get("IOTGW_DATA_DIR", "").strip()
    if override:
        return Path(override).expanduser()
    if os.name == "nt":
        base = os.environ.get("APPDATA") or str(Path.home())
        return Path(base) / "IoTGatewayMonitor"
    return Path.home() / ".local" / "share" / "iot-gateway-monitor"


@dataclass(frozen=True)
class Settings:
    host: str = "127.0.0.1"
    port: int = 9137
    data_dir: Path = Path(".")
    registry_path: Path = Path("registry.sqlite")
    api_token: str | None = None
    ssh_key_path: str | None = None
    ssh_password: str | None = None
    ca_passphrase: str | None = None
    allow_unknown_host: bool = False
    loki_url: str = "http://127.0.0.1:3100"
    prometheus_url: str = "http://127.0.0.1:9090"

    @classmethod
    def from_env(cls) -> "Settings":
        data_dir = _default_data_dir()
        reg = os.environ.get("IOTGW_REGISTRY_PATH", "").strip()
        registry_path = Path(reg).expanduser() if reg else data_dir / "registry.sqlite"
        token = os.environ.get("IOTGW_API_TOKEN", "").strip() or None
        key = os.environ.get("IOTGW_SSH_KEY", "").strip() or None
        pw = os.environ.get("IOTGW_SSH_PASSWORD")  # may be empty string
        if pw is not None and pw == "":
            pw = None
        ca = os.environ.get("IOTGW_CA_PASSPHRASE")
        if ca is not None and ca == "":
            ca = None
        allow = os.environ.get("IOTGW_SSH_ALLOW_UNKNOWN", "").strip().lower() in (
            "1",
            "true",
            "yes",
        )
        loki = (
            os.environ.get("LOKI_URL")
            or os.environ.get("IOTGW_LOKI_URL")
            or "http://127.0.0.1:3100"
        ).strip()
        prom = (
            os.environ.get("PROMETHEUS_URL")
            or os.environ.get("IOTGW_PROMETHEUS_URL")
            or "http://127.0.0.1:9090"
        ).strip()
        return cls(
            host=os.environ.get("IOTGW_CONTROL_HOST", "127.0.0.1").strip() or "127.0.0.1",
            port=int(os.environ.get("IOTGW_CONTROL_PORT", "9137") or "9137"),
            data_dir=data_dir,
            registry_path=registry_path,
            api_token=token,
            ssh_key_path=key,
            ssh_password=pw,
            ca_passphrase=ca,
            allow_unknown_host=allow,
            loki_url=loki or "http://127.0.0.1:3100",
            prometheus_url=prom or "http://127.0.0.1:9090",
        )
