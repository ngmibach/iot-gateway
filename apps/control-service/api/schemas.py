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


class RegisterDeviceRequest(BaseModel):
    user_id: str = Field(..., min_length=1, max_length=64)
    password: str = Field(..., min_length=8)
    ip: str = Field(..., min_length=1)
    topic_read: Optional[Union[str, list[str]]] = None
    topic_readwrite: Optional[Union[str, list[str]]] = None
    monitor_enabled: bool = True
    ca_passphrase: Optional[str] = None
    reissue_cert: bool = False

    @field_validator("user_id")
    @classmethod
    def _strip_user(cls, v: str) -> str:
        return v.strip()

    @field_validator("ip")
    @classmethod
    def _strip_ip(cls, v: str) -> str:
        return v.strip()

    def topics_r(self) -> list[str]:
        return _as_topic_list(self.topic_read)

    def topics_rw(self) -> list[str]:
        return _as_topic_list(self.topic_readwrite)

    def topic_r_arg(self) -> str | None:
        items = self.topics_r()
        return items[0] if items else None

    def topic_rw_arg(self) -> str | None:
        items = self.topics_rw()
        return items[0] if items else None


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


class RegisterDeviceResponse(BaseModel):
    device: DeviceOut
    cert_bundle_token: Optional[str] = None
    status: str = "ok"
    message: str = ""
    idempotent: bool = False


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
    # Prometheus $node label / instance — registry-driven for Streamlit
    node_instance: str
