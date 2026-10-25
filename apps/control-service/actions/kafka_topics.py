"""Logical Kafka topic catalog stored on the gateway.

The catalog records one retention-capped topic per registered sensor. A real
Kafka/Redpanda broker will consume this catalog later; registration already
enforces the storage budget so the gateway cannot over-commit disk.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Any, Optional

from .kafka_capacity import (
    DEFAULT_TOPIC_RETENTION_BYTES,
    STORAGE_SAFETY_RATIO,
    kafka_topic_name,
)


CATALOG_VERSION = 1


@dataclass
class TopicRecord:
    device_id: str
    topic: str
    retention_bytes: int
    created_at: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "device_id": self.device_id,
            "topic": self.topic,
            "retention_bytes": self.retention_bytes,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any], *, fallback_device_id: str = "") -> "TopicRecord":
        device_id = str(data.get("device_id") or fallback_device_id).strip()
        topic = str(data.get("topic") or kafka_topic_name(device_id)).strip()
        retention = int(data.get("retention_bytes") or DEFAULT_TOPIC_RETENTION_BYTES)
        created = int(data.get("created_at") or 0)
        return cls(
            device_id=device_id,
            topic=topic,
            retention_bytes=retention,
            created_at=created,
        )


@dataclass
class TopicCatalog:
    """In-memory view of ``kafka/topics.json`` on the gateway."""

    retention_bytes_default: int = DEFAULT_TOPIC_RETENTION_BYTES
    safety_ratio: float = STORAGE_SAFETY_RATIO
    topics: dict[str, TopicRecord] | None = None
    version: int = CATALOG_VERSION

    def __post_init__(self) -> None:
        if self.topics is None:
            self.topics = {}

    @property
    def count(self) -> int:
        assert self.topics is not None
        return len(self.topics)

    def get_by_device(self, device_id: str) -> Optional[TopicRecord]:
        assert self.topics is not None
        want = device_id.strip()
        for rec in self.topics.values():
            if rec.device_id == want:
                return rec
        topic = kafka_topic_name(want)
        return self.topics.get(topic)

    def upsert_device(
        self,
        device_id: str,
        *,
        retention_bytes: int | None = None,
        created_at: int | None = None,
    ) -> TopicRecord:
        """Create or refresh the topic record for ``device_id``."""
        assert self.topics is not None
        existing = self.get_by_device(device_id)
        topic = kafka_topic_name(device_id)
        retention = int(
            retention_bytes
            if retention_bytes is not None
            else (
                existing.retention_bytes
                if existing is not None
                else self.retention_bytes_default
            )
        )
        ts = int(
            created_at
            if created_at is not None
            else (existing.created_at if existing is not None else int(time.time()))
        )
        # Drop any stale key if topic naming changed.
        if existing is not None and existing.topic != topic:
            self.topics.pop(existing.topic, None)
        rec = TopicRecord(
            device_id=device_id.strip(),
            topic=topic,
            retention_bytes=retention,
            created_at=ts,
        )
        self.topics[topic] = rec
        return rec

    def remove_device(self, device_id: str) -> Optional[TopicRecord]:
        assert self.topics is not None
        existing = self.get_by_device(device_id)
        if existing is None:
            return None
        return self.topics.pop(existing.topic, None)

    def to_dict(self) -> dict[str, Any]:
        assert self.topics is not None
        return {
            "version": self.version,
            "retention_bytes_default": self.retention_bytes_default,
            "safety_ratio": self.safety_ratio,
            "topics": {k: v.to_dict() for k, v in sorted(self.topics.items())},
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, sort_keys=True) + "\n"

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> "TopicCatalog":
        if not data:
            return cls()
        raw_topics = data.get("topics") or {}
        topics: dict[str, TopicRecord] = {}
        if isinstance(raw_topics, dict):
            for key, value in raw_topics.items():
                if not isinstance(value, dict):
                    continue
                rec = TopicRecord.from_dict(value, fallback_device_id=str(key))
                topics[rec.topic] = rec
        retention = int(
            data.get("retention_bytes_default") or DEFAULT_TOPIC_RETENTION_BYTES
        )
        ratio = float(data.get("safety_ratio") or STORAGE_SAFETY_RATIO)
        version = int(data.get("version") or CATALOG_VERSION)
        return cls(
            retention_bytes_default=retention,
            safety_ratio=ratio,
            topics=topics,
            version=version,
        )

    @classmethod
    def from_json(cls, text: str | None) -> "TopicCatalog":
        if not text or not text.strip():
            return cls()
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ValueError(f"invalid kafka topic catalog JSON: {exc}") from exc
        if not isinstance(data, dict):
            raise ValueError("kafka topic catalog must be a JSON object")
        return cls.from_dict(data)


class CapacityExceededError(Exception):
    """Raised when a new sensor would exceed the gateway Kafka storage budget."""

    def __init__(
        self,
        message: str,
        *,
        max_sensors: int,
        registered_sensors: int,
        topic_retention_bytes: int,
        total_storage_bytes: int,
    ) -> None:
        super().__init__(message)
        self.max_sensors = max_sensors
        self.registered_sensors = registered_sensors
        self.topic_retention_bytes = topic_retention_bytes
        self.total_storage_bytes = total_storage_bytes
