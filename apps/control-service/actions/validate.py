"""Input validation for device actions."""

from __future__ import annotations

import ipaddress
import re

from .paths import RESERVED_USERNAMES

# MQTT filter: topic levels + optional trailing # / single-level +
_TOPIC_RE = re.compile(r"^[^\s#\+]*(?:/(?:[^\s#\+]+|\+))*(?:/#)?$|^#$|^\+$")
_USER_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


def validate_user_id(user_id: str) -> str:
    if not user_id or not _USER_RE.match(user_id):
        raise ValueError(f"invalid user_id: {user_id!r}")
    if user_id.lower() in RESERVED_USERNAMES:
        raise ValueError(f"user_id {user_id!r} is reserved")
    return user_id


def validate_ip_or_cidr(value: str) -> str:
    value = value.strip()
    if not value:
        raise ValueError("empty IP/CIDR")
    try:
        if "/" in value:
            ipaddress.ip_network(value, strict=False)
        else:
            ipaddress.ip_address(value)
    except ValueError as exc:
        raise ValueError(f"invalid IP/CIDR: {value!r}") from exc
    return value


def validate_topic(topic: str) -> str:
    topic = topic.strip()
    if not topic:
        raise ValueError("empty MQTT topic")
    if "\n" in topic or "\r" in topic:
        raise ValueError(f"invalid MQTT topic: {topic!r}")
    # Allow common patterns including sensors/foo/#
    if not _TOPIC_RE.match(topic) and not re.match(r"^[A-Za-z0-9_./+\-#$]+$", topic):
        raise ValueError(f"invalid MQTT topic: {topic!r}")
    return topic


def split_csv(value: str | None) -> list[str]:
    if not value or value.strip().lower() == "none":
        return []
    return [p.strip() for p in value.split(",") if p.strip()]
