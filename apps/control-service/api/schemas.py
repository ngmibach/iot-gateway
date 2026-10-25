"""Pydantic request/response models for device control API."""

from __future__ import annotations

from typing import Any, Optional, Union

from pydantic import BaseModel, Field, field_validator


def _as_topic_list(value: Union[str, list[str], None]) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        text = value.strip()
        return [text] if text else []
    return [str(v).strip() for v in value if str(v).strip()]


def _one_topic(value: Union[str, list[str], None], field_name: str) -> Optional[str]:
    """Playbook accepts a single topic today — reject multi-topic lists."""
    items = _as_topic_list(value)
    if not items:
        return None
    if len(items) > 1:
        raise ValueError(
            f"{field_name}: only one topic supported until multi-topic playbook exists"
        )
    return items[0]


class RegisterDeviceRequest(BaseModel):
    user_id: str = Field(..., min_length=1, max_length=64)
    password: str = Field(..., min_length=8)
    ip: str = Field(..., min_length=1)
    topic_read: Optional[Union[str, list[str]]] = None
    topic_readwrite: Optional[Union[str, list[str]]] = None
    monitor_enabled: bool = True
    ca_passphrase: Optional[str] = None

    @field_validator("user_id")
    @classmethod
    def _strip_user(cls, v: str) -> str:
        return v.strip()

    @field_validator("ip")
    @classmethod
    def _strip_ip(cls, v: str) -> str:
        return v.strip()

    @field_validator("topic_read", "topic_readwrite")
    @classmethod
    def _single_topic(cls, v: Union[str, list[str], None], info) -> Union[str, list[str], None]:
        _one_topic(v, info.field_name)
        return v

    def topics_r(self) -> list[str]:
        return _as_topic_list(self.topic_read)

    def topics_rw(self) -> list[str]:
        return _as_topic_list(self.topic_readwrite)

    def topic_r_arg(self) -> str | None:
        return _one_topic(self.topic_read, "topic_read")

    def topic_rw_arg(self) -> str | None:
        return _one_topic(self.topic_readwrite, "topic_readwrite")


class DeviceOut(BaseModel):
    id: str
    gateway_id: str
    ip: Optional[str] = None
    topics_rw: Optional[Any] = None
    topics_r: Optional[Any] = None
    monitor_enabled: bool = True
    cert_expires_at: Optional[int] = None
    cert_fingerprint: Optional[str] = None
    created_at: Optional[int] = None
    kafka_topic: Optional[str] = None
    kafka_retention_bytes: Optional[int] = None


class KafkaCapacityOut(BaseModel):
    """Gateway sensor slots from disk size × 70% / per-topic retention cap."""

    total_storage_bytes: int
    topic_retention_bytes: int
    safety_ratio: float
    budget_bytes: int
    max_sensors: int
    registered_sensors: int
    remaining_slots: int
    at_capacity: bool = False


class UpdateDeviceRequest(BaseModel):
    """Partial device update from Control Plane View.

    Monitor-only changes stay in the local registry. IP / topic / password
    changes re-run the register playbook and require ``password``.
    """

    password: Optional[str] = Field(default=None, min_length=8)
    ip: Optional[str] = None
    topic_read: Optional[Union[str, list[str]]] = None
    topic_readwrite: Optional[Union[str, list[str]]] = None
    monitor_enabled: Optional[bool] = None
    ca_passphrase: Optional[str] = None

    @field_validator("ip")
    @classmethod
    def _strip_ip(cls, v: Optional[str]) -> Optional[str]:
        return v.strip() if isinstance(v, str) else v

    @field_validator("topic_read", "topic_readwrite")
    @classmethod
    def _single_topic(
        cls, v: Union[str, list[str], None], info
    ) -> Union[str, list[str], None]:
        _one_topic(v, info.field_name)
        return v

    def topics_r(self) -> list[str]:
        return _as_topic_list(self.topic_read)

    def topics_rw(self) -> list[str]:
        return _as_topic_list(self.topic_readwrite)

    def topic_r_arg(self) -> str | None:
        return _one_topic(self.topic_read, "topic_read")

    def topic_rw_arg(self) -> str | None:
        return _one_topic(self.topic_readwrite, "topic_readwrite")


class UpdateDeviceResponse(BaseModel):
    device: DeviceOut
    cert_bundle_token: Optional[str] = None
    status: str = "ok"
    message: str = ""
    playbook: bool = False


class DiscoverSensorsResponse(BaseModel):
    hosts: list[dict[str, Any]] = Field(default_factory=list)
    gateway_ips: list[str] = Field(default_factory=list)


class ReissueCertRequest(BaseModel):
    ca_passphrase: Optional[str] = None
    days: int = Field(default=730, ge=1, le=3650)


class ReissueCertResponse(BaseModel):
    device: DeviceOut
    cert_bundle_token: Optional[str] = None
    status: str = "ok"
    message: str = ""


class RegisterDeviceResponse(BaseModel):
    device: DeviceOut
    cert_bundle_token: Optional[str] = None
    status: str = "ok"
    message: str = ""
    # True when a devices row already existed for (gateway_id, user_id) before upsert.
    idempotent: bool = Field(
        default=False,
        description="True if device row already existed; playbook still ran (full upsert).",
    )
    kafka_topic: Optional[str] = None
    kafka_capacity: Optional[KafkaCapacityOut] = None


class HealthResponse(BaseModel):
    status: str = "ok"


class GatewayOut(BaseModel):
    id: str
    host: str
    ssh_user: str
    install_root: str
    fingerprint: str
    monitoring_ip: Optional[str] = None
    status: Optional[str] = None
    # Fixed label matching deploy/templates prometheus `instance: gateway`.
    node_instance: str = "gateway"


class RotateServerRequest(BaseModel):
    gateway_ip: Optional[str] = None
    ca_passphrase: Optional[str] = None
    days: int = Field(default=730, ge=1, le=3650)


class RotateServerResponse(BaseModel):
    ok: bool
    status: str = "ok"
    message: str = ""
    gateway_ip: str
    not_valid_after: Optional[str] = None
    fingerprint_sha256: Optional[str] = None


class RotateCARequest(BaseModel):
    gateway_ip: Optional[str] = None
    ca_passphrase: Optional[str] = None
    confirm_break_glass: bool = False
    # None → reissue every registry device for this gateway.
    device_ids: Optional[list[str]] = None


class DeviceBundleToken(BaseModel):
    device_id: str
    cert_bundle_token: str
    fingerprint_sha256: Optional[str] = None
    not_valid_after: Optional[str] = None


class RotateCAResponse(BaseModel):
    ok: bool
    status: str = "ok"
    message: str = ""
    gateway_ip: str
    # Only redistribute when ok=True (reload_failed keeps tokens but UI must warn).
    redistribute: bool = False
    devices: list[DeviceBundleToken] = Field(default_factory=list)
