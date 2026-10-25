"""Kafka topic retention planning for the gateway agent.

Incoming sensor messages land in Mosquitto, then are stored in a per-sensor
Kafka topic with a hard ``retention.bytes`` cap. Sensor registration capacity
is derived from total gateway disk:

    max_sensors = floor(total_disk_bytes * SAFETY_RATIO / topic_retention_bytes)

With the default safety ratio of 0.70, a 10-unit disk and 1-unit topic cap
allows 7 sensors. The control-service writes the topic catalog under
``/var/lib/iot-gateway-agent/kafka/topics.json``; a real Kafka/Redpanda broker
will be provisioned in a follow-up to enforce these retention caps on disk.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

STORAGE_SAFETY_RATIO = 0.70
DEFAULT_TOPIC_RETENTION_BYTES = 1 * 1024**3
CATALOG_NAME = "topics.json"


def kafka_topic_name(device_id: str) -> str:
    return f"sensor.{device_id.strip()}"


def max_sensor_slots(
    total_storage_bytes: int,
    topic_retention_bytes: int = DEFAULT_TOPIC_RETENTION_BYTES,
    *,
    safety_ratio: float = STORAGE_SAFETY_RATIO,
) -> int:
    if total_storage_bytes <= 0 or topic_retention_bytes <= 0 or safety_ratio <= 0:
        return 0
    budget = int(total_storage_bytes * min(safety_ratio, 1.0))
    return budget // int(topic_retention_bytes)


def total_storage_bytes(path: str | Path = "/") -> int:
    """Return filesystem total size for ``path`` via ``os.statvfs``."""
    st = os.statvfs(str(path))
    return int(st.f_frsize * st.f_blocks)


@dataclass(frozen=True)
class CapacitySnapshot:
    total_storage_bytes: int
    topic_retention_bytes: int
    safety_ratio: float
    max_sensors: int
    registered_sensors: int
    remaining_slots: int

    @property
    def at_capacity(self) -> bool:
        return self.remaining_slots <= 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_storage_bytes": self.total_storage_bytes,
            "topic_retention_bytes": self.topic_retention_bytes,
            "safety_ratio": self.safety_ratio,
            "max_sensors": self.max_sensors,
            "registered_sensors": self.registered_sensors,
            "remaining_slots": self.remaining_slots,
            "at_capacity": self.at_capacity,
        }


class TopicCatalog:
    """Read the on-disk Kafka topic catalog written by sensor registration."""

    def __init__(self, data_dir: str | Path):
        self.data_dir = Path(data_dir)
        self.path = self.data_dir / "kafka" / CATALOG_NAME
        self.retention_bytes_default = DEFAULT_TOPIC_RETENTION_BYTES
        self.safety_ratio = STORAGE_SAFETY_RATIO
        self.topics: dict[str, dict[str, Any]] = {}
        self.reload()

    def reload(self) -> None:
        if not self.path.is_file():
            self.topics = {}
            return
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            self.topics = {}
            return
        if not isinstance(data, dict):
            self.topics = {}
            return
        self.retention_bytes_default = int(
            data.get("retention_bytes_default") or DEFAULT_TOPIC_RETENTION_BYTES
        )
        self.safety_ratio = float(data.get("safety_ratio") or STORAGE_SAFETY_RATIO)
        raw = data.get("topics") or {}
        self.topics = raw if isinstance(raw, dict) else {}

    @property
    def count(self) -> int:
        return len(self.topics)

    def capacity(
        self, *, storage_path: str | Path | None = None
    ) -> CapacitySnapshot:
        total = total_storage_bytes(storage_path or self.data_dir)
        max_n = max_sensor_slots(
            total,
            self.retention_bytes_default,
            safety_ratio=self.safety_ratio,
        )
        registered = self.count
        return CapacitySnapshot(
            total_storage_bytes=total,
            topic_retention_bytes=self.retention_bytes_default,
            safety_ratio=self.safety_ratio,
            max_sensors=max_n,
            registered_sensors=registered,
            remaining_slots=max(0, max_n - registered),
        )


def topic_config_for_broker(
    device_id: str,
    *,
    retention_bytes: int = DEFAULT_TOPIC_RETENTION_BYTES,
) -> dict[str, Any]:
    """Return the Kafka topic create config a future broker provisioner will use."""
    return {
        "topic": kafka_topic_name(device_id),
        "config": {
            # Hard size cap so one sensor cannot exhaust gateway disk.
            "retention.bytes": str(int(retention_bytes)),
            # Keep time retention high; size is the binding constraint.
            "retention.ms": str(-1),
            "cleanup.policy": "delete",
        },
    }
