"""Best-effort produce of decrypted sensor payloads to local Apache Kafka (KRaft).

Sensors still publish over MQTT. After decrypt, the agent mirrors cleartext to
``sensor.<device_id>`` on ``127.0.0.1:9092``. Missing broker or client lib is
non-fatal — decrypt + log path continues.
"""

from __future__ import annotations

import logging
import threading
from typing import Any, Optional

logger = logging.getLogger(__name__)

DEFAULT_BOOTSTRAP = "127.0.0.1:9092"


class SensorKafkaProducer:
    """Thin wrapper around kafka-python KafkaProducer (lazy connect)."""

    def __init__(self, *, bootstrap: str = DEFAULT_BOOTSTRAP):
        self.bootstrap = bootstrap
        self._producer: Any = None
        self._lock = threading.Lock()
        self._disabled_reason: Optional[str] = None
        self.produced_ok = 0
        self.produced_fail = 0
        self.up = False

    def close(self) -> None:
        with self._lock:
            prod = self._producer
            self._producer = None
            self.up = False
        if prod is not None:
            try:
                prod.flush(timeout=2)
                prod.close(timeout=2)
            except Exception:  # noqa: BLE001
                pass

    def _ensure(self) -> Any | None:
        if self._disabled_reason:
            return None
        if self._producer is not None:
            return self._producer
        with self._lock:
            if self._producer is not None:
                return self._producer
            if self._disabled_reason:
                return None
            try:
                from kafka import KafkaProducer  # type: ignore[import-untyped]
            except ImportError:
                self._disabled_reason = "kafka-python not installed"
                logger.warning("%s — Kafka produce disabled", self._disabled_reason)
                self.up = False
                return None
            try:
                self._producer = KafkaProducer(
                    bootstrap_servers=self.bootstrap,
                    value_serializer=lambda v: v
                    if isinstance(v, (bytes, bytearray))
                    else str(v).encode("utf-8"),
                    acks=1,
                    retries=1,
                    request_timeout_ms=5000,
                    max_block_ms=3000,
                    linger_ms=50,
                )
                self.up = True
                logger.info("Kafka producer connected to %s", self.bootstrap)
            except Exception as exc:  # noqa: BLE001
                self._disabled_reason = f"connect failed: {exc}"
                self.up = False
                logger.warning(
                    "Kafka producer unavailable (%s) — will retry later",
                    self._disabled_reason,
                )
                # Allow retry on next message.
                self._disabled_reason = None
                return None
            return self._producer

    def produce(self, topic: str, value: str | bytes) -> bool:
        """Send one record. Returns True on accepted send (async)."""
        topic = (topic or "").strip()
        if not topic:
            return False
        prod = self._ensure()
        if prod is None:
            self.produced_fail += 1
            return False
        try:
            raw = value if isinstance(value, (bytes, bytearray)) else value.encode("utf-8")
            prod.send(topic, raw)
            self.produced_ok += 1
            self.up = True
            return True
        except Exception as exc:  # noqa: BLE001
            self.produced_fail += 1
            self.up = False
            logger.debug("Kafka produce to %s failed: %s", topic, exc)
            # Drop cached producer so next call reconnects.
            with self._lock:
                try:
                    if self._producer is not None:
                        self._producer.close(timeout=1)
                except Exception:  # noqa: BLE001
                    pass
                self._producer = None
            return False
