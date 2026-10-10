"""Minimal Prometheus text exposition for the monolithic agent."""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .decrypt_worker import DecryptWorker
    from .shipper import LokiShipper


@dataclass
class AgentMetrics:
    started_at: float = field(default_factory=time.time)
    mqtt_up: bool = False
    decrypt_worker: DecryptWorker | None = None
    shipper: LokiShipper | None = None

    def render(self) -> str:
        uptime = time.time() - self.started_at
        ok = self.decrypt_worker.messages_ok if self.decrypt_worker else 0
        fail = self.decrypt_worker.messages_fail if self.decrypt_worker else 0
        sent = self.shipper.lines_sent if self.shipper else 0
        # Lightweight host gauges
        load1 = 0.0
        try:
            load1 = os.getloadavg()[0]
        except (OSError, AttributeError):
            pass
        mem_total = mem_avail = 0
        try:
            with open("/proc/meminfo", encoding="utf-8") as f:
                for line in f:
                    if line.startswith("MemTotal:"):
                        mem_total = int(line.split()[1]) * 1024
                    elif line.startswith("MemAvailable:"):
                        mem_avail = int(line.split()[1]) * 1024
        except OSError:
            pass
        lines = [
            "# HELP iotgw_agent_up Agent process up",
            "# TYPE iotgw_agent_up gauge",
            "iotgw_agent_up 1",
            "# HELP iotgw_agent_uptime_seconds Uptime",
            "# TYPE iotgw_agent_uptime_seconds gauge",
            f"iotgw_agent_uptime_seconds {uptime:.3f}",
            "# HELP iotgw_mqtt_up Mosquitto child running",
            "# TYPE iotgw_mqtt_up gauge",
            f"iotgw_mqtt_up {1 if self.mqtt_up else 0}",
            "# HELP iotgw_decrypt_messages_total Decrypted messages",
            "# TYPE iotgw_decrypt_messages_total counter",
            f'iotgw_decrypt_messages_total{{result="ok"}} {ok}',
            f'iotgw_decrypt_messages_total{{result="fail"}} {fail}',
            "# HELP iotgw_loki_lines_sent_total Lines shipped to Loki",
            "# TYPE iotgw_loki_lines_sent_total counter",
            f"iotgw_loki_lines_sent_total {sent}",
            "# HELP node_load1 Load average (compat name for dashboards)",
            "# TYPE node_load1 gauge",
            f"node_load1 {load1}",
            "# HELP node_memory_MemTotal_bytes Memory total",
            "# TYPE node_memory_MemTotal_bytes gauge",
            f"node_memory_MemTotal_bytes {mem_total}",
            "# HELP node_memory_MemAvailable_bytes Memory available",
            "# TYPE node_memory_MemAvailable_bytes gauge",
            f"node_memory_MemAvailable_bytes {mem_avail}",
            "",
        ]
        return "\n".join(lines)
