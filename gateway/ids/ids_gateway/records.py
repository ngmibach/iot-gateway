from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict


@dataclass
class PacketRecord:
    ts: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    proto: str
    pkt_len: int
    tcp_flags: str
    observed_src_ip: str = ""
    mqtt_topic: str = ""
    mqtt_device_id: str = ""
    mqtt_payload: Any = None
    mqtt_delay: float = 0.0
    gateway_received_at: str = ""
    device_reported_at: str = ""
    test_phase: str = ""
    capture_mode: str = "sensor_log"
    semantic_quality: str = "HIGH"
    event_ts_source: str = "packet"
    extra: Dict[str, Any] = field(default_factory=dict)