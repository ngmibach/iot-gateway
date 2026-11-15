"""Kafka topic capacity planning for gateway sensor registration.

Each registered sensor owns one Kafka topic with a fixed retention-size cap.
The gateway may only register enough sensors to stay within a safety fraction
of total gateway disk (default 70%).

Example (abstract units): topic_cap=1, disk=10 → max_sensors = floor(10*0.7/1) = 7.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Optional

from .shellutil import shell_quote

# Topic names used in unquoted glob tails after a quoted base path.
_TOPIC_GLOB_SAFE_RE = re.compile(r"^[A-Za-z0-9._-]+$")

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


def topic_name_from_log_dir(dirname: str) -> str:
    """Map Kafka log dir ``sensor.fake1-0`` → topic ``sensor.fake1``."""
    name = (dirname or "").rstrip("/").rsplit("/", 1)[-1]
    if "-" not in name:
        return name
    topic, _, maybe_part = name.rpartition("-")
    if maybe_part.isdigit() and topic:
        return topic
    return name


def parse_du_topic_sizes(stdout: str) -> dict[str, int]:
    """Sum ``du -sb`` lines into ``{topic: used_bytes}`` (multi-partition safe)."""
    out: dict[str, int] = {}
    for raw in (stdout or "").splitlines():
        line = raw.strip()
        if not line:
            continue
        parts = line.split(None, 1)
        if len(parts) < 2:
            continue
        try:
            size = int(parts[0])
        except ValueError:
            continue
        if size < 0:
            continue
        topic = topic_name_from_log_dir(parts[1])
        if not topic or "*" in topic:
            continue
        out[topic] = int(out.get(topic, 0)) + size
    return out


def _topic_glob_fragment(topic: str) -> str | None:
    """Return topic text safe to place unquoted after a quoted ``du`` base path."""
    name = str(topic or "").strip()
    if not name or not _TOPIC_GLOB_SAFE_RE.fullmatch(name):
        return None
    return name


def probe_topic_used_bytes_map(
    ssh: "SSHClient",
    data_dir: str,
    topics: list[str] | None = None,
) -> dict[str, int]:
    """Return on-disk Kafka log bytes per topic under ``{data_dir}/kafka/data``.

    Missing topic dirs yield no entry (caller may treat as 0). Command failures
    with empty stdout return ``{}``; callers should not treat that as SSH auth
    failure (use the surrounding connect error for that).

    Globs must keep ``*`` outside shell quotes — quoting ``…/sensor.x-*`` makes
    ``du`` look for a literal path and report 0 usage while topics have data.
    """
    base = f"{str(data_dir).rstrip('/')}/kafka/data"
    quoted_base = shell_quote(base)
    cleaned: list[str] = []
    if topics:
        cleaned = [str(t).strip() for t in topics if str(t).strip()]
        if not cleaned:
            return {}
        fragments: list[str] = []
        for t in cleaned:
            frag = _topic_glob_fragment(t)
            if frag is None:
                continue
            # Quote only the directory; leave "/topic-*" unquoted for expansion.
            fragments.append(f"{quoted_base}/{frag}-*")
        if fragments:
            cmd = f"du -sb -- {' '.join(fragments)} 2>/dev/null || true"
        else:
            cmd = f"du -sb -- {quoted_base}/* 2>/dev/null || true"
    else:
        cmd = f"du -sb -- {quoted_base}/* 2>/dev/null || true"
    result = ssh.run(cmd, timeout=30.0)
    sizes = parse_du_topic_sizes(getattr(result, "stdout", "") or "")
    if not cleaned:
        return sizes
    return {t: int(sizes[t]) for t in cleaned if t in sizes}


def probe_topic_used_bytes(
    ssh: "SSHClient",
    data_dir: str,
    topic: str,
) -> int | None:
    """Return used bytes for one topic, or None when the probe yields nothing useful."""
    name = str(topic or "").strip()
    if not name:
        return None
    sizes = probe_topic_used_bytes_map(ssh, data_dir, topics=[name])
    if name not in sizes:
        # No matching log dirs → empty topic (0), distinct from probe hard-fail.
        return 0
    return int(sizes[name])
