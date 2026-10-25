"""Kafka topic capacity planning for gateway sensor registration.

Each registered sensor owns one Kafka topic with a fixed retention-size cap.
The gateway may only register enough sensors to stay within a safety fraction
of total gateway disk (default 70%).

Example (abstract units): topic_cap=1, disk=10 → max_sensors = floor(10*0.7/1) = 7.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Optional

from .shellutil import shell_quote

if TYPE_CHECKING:
    from .ssh import SSHClient

# Leave headroom for OS, Mosquitto, logs, and agent data.
STORAGE_SAFETY_RATIO = 0.70

# Default per-topic retention.bytes (1 GiB). Override via catalog / settings.
DEFAULT_TOPIC_RETENTION_BYTES = 1 * 1024**3


@dataclass(frozen=True)
class CapacityPlan:
    """Snapshot of how many sensors the gateway may hold."""

    total_storage_bytes: int
    topic_retention_bytes: int
    safety_ratio: float
    budget_bytes: int
    max_sensors: int
    registered_sensors: int
    remaining_slots: int

    @property
    def at_capacity(self) -> bool:
        return self.remaining_slots <= 0


def kafka_topic_name(device_id: str) -> str:
    """Stable Kafka topic name for a sensor device id."""
    return f"sensor.{device_id.strip()}"


def max_sensor_slots(
    total_storage_bytes: int,
    topic_retention_bytes: int = DEFAULT_TOPIC_RETENTION_BYTES,
    *,
    safety_ratio: float = STORAGE_SAFETY_RATIO,
) -> int:
    """Return floor(total * safety_ratio / topic_cap).

    Uses total filesystem size (not free space) so the registration budget is
    stable as Kafka fills retained segments.
    """
    if total_storage_bytes <= 0 or topic_retention_bytes <= 0:
        return 0
    if safety_ratio <= 0:
        return 0
    ratio = min(safety_ratio, 1.0)
    budget = int(total_storage_bytes * ratio)
    return budget // int(topic_retention_bytes)


def plan_capacity(
    *,
    total_storage_bytes: int,
    registered_sensors: int,
    topic_retention_bytes: int = DEFAULT_TOPIC_RETENTION_BYTES,
    safety_ratio: float = STORAGE_SAFETY_RATIO,
) -> CapacityPlan:
    """Build a capacity plan from disk size and current topic count."""
    registered = max(0, int(registered_sensors))
    retention = int(topic_retention_bytes) if topic_retention_bytes > 0 else 0
    ratio = float(safety_ratio)
    max_n = max_sensor_slots(
        total_storage_bytes,
        retention or DEFAULT_TOPIC_RETENTION_BYTES,
        safety_ratio=ratio,
    )
    budget = int(max(0, total_storage_bytes) * min(max(ratio, 0.0), 1.0))
    remaining = max(0, max_n - registered)
    return CapacityPlan(
        total_storage_bytes=max(0, int(total_storage_bytes)),
        topic_retention_bytes=retention or DEFAULT_TOPIC_RETENTION_BYTES,
        safety_ratio=ratio,
        budget_bytes=budget,
        max_sensors=max_n,
        registered_sensors=registered,
        remaining_slots=remaining,
    )


def parse_df_total_bytes(df_line: str) -> Optional[int]:
    """Parse ``df -Pk`` data line; size column is 1K-blocks (index 1)."""
    line = df_line.strip().splitlines()[-1] if df_line.strip() else ""
    parts = line.split()
    if len(parts) < 2:
        return None
    try:
        size_k = int(parts[1])
    except ValueError:
        return None
    if size_k < 0:
        return None
    return size_k * 1024


def probe_total_storage_bytes(
    ssh: "SSHClient",
    path: str,
) -> int:
    """Return total filesystem size in bytes for ``path`` via ``df -Pk``."""
    quoted = shell_quote(path)
    result = ssh.run(f"df -Pk {quoted} | tail -1", timeout=15.0)
    if getattr(result, "exit_code", 1) != 0:
        raise RuntimeError(
            f"df failed for {path}: {getattr(result, 'stderr', '') or getattr(result, 'stdout', '')}"
        )
    total = parse_df_total_bytes(getattr(result, "stdout", "") or "")
    if total is None:
        raise RuntimeError(f"could not parse df output for {path}: {result.stdout!r}")
    return total
