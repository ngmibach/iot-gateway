"""Prometheus text exposition for the monolithic agent (incl. node_* compat)."""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from .broker import MosquittoSupervisor
    from .decrypt_worker import DecryptWorker
    from .shipper import LokiShipper


def _read_meminfo() -> dict[str, int]:
    out: dict[str, int] = {}
    try:
        with open("/proc/meminfo", encoding="utf-8") as f:
            for line in f:
                parts = line.split()
                if len(parts) < 2:
                    continue
                key = parts[0].rstrip(":")
                try:
                    out[key] = int(parts[1]) * 1024
                except ValueError:
                    continue
    except OSError:
        pass
    return out


_CPU_MODES = (
    "user",
    "nice",
    "system",
    "idle",
    "iowait",
    "irq",
    "softirq",
    "steal",
    "guest",
    "guest_nice",
)


def _read_cpu_seconds_by_core() -> list[tuple[str, dict[str, float]]]:
    """Per-CPU cumulative seconds by mode (node_exporter-compatible)."""
    try:
        hz = float(os.sysconf("SC_CLK_TCK") or 100)
    except (ValueError, OSError, AttributeError):
        hz = 100.0
    rows: list[tuple[str, dict[str, float]]] = []
    try:
        with open("/proc/stat", encoding="utf-8") as f:
            for line in f:
                if not line.startswith("cpu") or line.startswith("cpu "):
                    continue
                if not line[3:4].isdigit():
                    continue
                parts = line.split()
                cpu = parts[0][3:]  # "0", "1", …
                vals: dict[str, float] = {}
                for i, name in enumerate(_CPU_MODES):
                    if i + 1 >= len(parts):
                        break
                    try:
                        vals[name] = int(parts[i + 1]) / hz
                    except ValueError:
                        continue
                if vals:
                    rows.append((cpu, vals))
    except OSError:
        return []
    return rows


def _read_fs_bytes(path: str = "/") -> tuple[int, int]:
    """Return (size_bytes, avail_bytes) for path."""
    try:
        st = os.statvfs(path)
    except OSError:
        return 0, 0
    size = int(st.f_frsize * st.f_blocks)
    avail = int(st.f_frsize * st.f_bavail)
    return size, avail


def _read_boot_time() -> float:
    try:
        with open("/proc/stat", encoding="utf-8") as f:
            for line in f:
                if line.startswith("btime "):
                    return float(line.split()[1])
    except (OSError, ValueError, IndexError):
        pass
    return 0.0


def _read_procs() -> tuple[int, int]:
    running = blocked = 0
    try:
        with open("/proc/stat", encoding="utf-8") as f:
            for line in f:
                if line.startswith("procs_running "):
                    running = int(line.split()[1])
                elif line.startswith("procs_blocked "):
                    blocked = int(line.split()[1])
    except (OSError, ValueError, IndexError):
        pass
    return running, blocked


def _read_net_bytes() -> list[tuple[str, int, int]]:
    rows: list[tuple[str, int, int]] = []
    try:
        with open("/proc/net/dev", encoding="utf-8") as f:
            lines = f.readlines()[2:]
    except OSError:
        return rows
    for line in lines:
        if ":" not in line:
            continue
        name, rest = line.split(":", 1)
        name = name.strip()
        parts = rest.split()
        if len(parts) < 9:
            continue
        try:
            rx = int(parts[0])
            tx = int(parts[8])
        except ValueError:
            continue
        rows.append((name, rx, tx))
    return rows


def _read_temp_c() -> float | None:
    """Best-effort SoC temperature (°C)."""
    candidates = [
        Path("/sys/class/thermal/thermal_zone0/temp"),
        Path("/sys/devices/virtual/thermal/thermal_zone0/temp"),
    ]
    for p in candidates:
        try:
            raw = int(p.read_text(encoding="utf-8").strip())
        except (OSError, ValueError):
            continue
        # Usually millidegrees.
        return raw / 1000.0 if raw > 200 else float(raw)
    return None


def _clk_tck() -> float:
    try:
        return float(os.sysconf("SC_CLK_TCK") or 100)
    except (ValueError, OSError, AttributeError):
        return 100.0


def _read_proc_rss_bytes(pid: int) -> Optional[int]:
    """Resident set size for ``pid`` from /proc/<pid>/statm (pages → bytes)."""
    try:
        with open(f"/proc/{pid}/statm", encoding="utf-8") as f:
            parts = f.read().split()
        if len(parts) < 2:
            return None
        pages = int(parts[1])
        return pages * os.sysconf("SC_PAGE_SIZE")
    except (OSError, ValueError, AttributeError):
        return None


def _read_proc_cpu_seconds(pid: int) -> Optional[float]:
    """Cumulative user+system CPU seconds for ``pid`` from /proc/<pid>/stat."""
    try:
        with open(f"/proc/{pid}/stat", encoding="utf-8") as f:
            raw = f.read()
        # comm may contain spaces/parentheses; fields after the last ')'.
        close = raw.rfind(")")
        if close < 0:
            return None
        parts = raw[close + 1 :].split()
        # After comm: state(0) … utime(11) stime(12) in 0-based post-comm fields.
        utime = int(parts[11])
        stime = int(parts[12])
        return (utime + stime) / _clk_tck()
    except (OSError, ValueError, IndexError):
        return None


def _host_metric_lines() -> list[str]:
    lines: list[str] = []
    load1 = 0.0
    try:
        load1 = os.getloadavg()[0]
    except (OSError, AttributeError):
        pass
    lines += [
        "# HELP node_load1 Load average (compat name for dashboards)",
        "# TYPE node_load1 gauge",
        f"node_load1 {load1}",
    ]

    mem = _read_meminfo()
    lines += [
        "# HELP node_memory_MemTotal_bytes Memory total",
        "# TYPE node_memory_MemTotal_bytes gauge",
        f"node_memory_MemTotal_bytes {mem.get('MemTotal', 0)}",
        "# HELP node_memory_MemAvailable_bytes Memory available",
        "# TYPE node_memory_MemAvailable_bytes gauge",
        f"node_memory_MemAvailable_bytes {mem.get('MemAvailable', 0)}",
        "# HELP node_memory_SwapTotal_bytes Swap total",
        "# TYPE node_memory_SwapTotal_bytes gauge",
        f"node_memory_SwapTotal_bytes {mem.get('SwapTotal', 0)}",
        "# HELP node_memory_SwapFree_bytes Swap free",
        "# TYPE node_memory_SwapFree_bytes gauge",
        f"node_memory_SwapFree_bytes {mem.get('SwapFree', 0)}",
    ]

    cpu_rows = _read_cpu_seconds_by_core()
    if cpu_rows:
        lines += [
            "# HELP node_cpu_seconds_total Seconds the CPUs spent in each mode",
            "# TYPE node_cpu_seconds_total counter",
        ]
        for cpu, modes in cpu_rows:
            for mode, value in modes.items():
                lines.append(
                    f'node_cpu_seconds_total{{cpu="{cpu}",mode="{mode}"}} {value:.6f}'
                )

    fs_size, fs_avail = _read_fs_bytes("/")
    lines += [
        "# HELP node_filesystem_size_bytes Filesystem size",
        "# TYPE node_filesystem_size_bytes gauge",
        f'node_filesystem_size_bytes{{mountpoint="/"}} {fs_size}',
        "# HELP node_filesystem_avail_bytes Filesystem avail",
        "# TYPE node_filesystem_avail_bytes gauge",
        f'node_filesystem_avail_bytes{{mountpoint="/"}} {fs_avail}',
    ]

    now = time.time()
    boot = _read_boot_time()
    lines += [
        "# HELP node_time_seconds System time",
        "# TYPE node_time_seconds gauge",
        f"node_time_seconds {now:.3f}",
        "# HELP node_boot_time_seconds Boot time",
        "# TYPE node_boot_time_seconds gauge",
        f"node_boot_time_seconds {boot:.3f}",
    ]

    running, blocked = _read_procs()
    lines += [
        "# HELP node_procs_running Running processes",
        "# TYPE node_procs_running gauge",
        f"node_procs_running {running}",
        "# HELP node_procs_blocked Blocked processes",
        "# TYPE node_procs_blocked gauge",
        f"node_procs_blocked {blocked}",
    ]

    net = _read_net_bytes()
    if net:
        lines += [
            "# HELP node_network_receive_bytes_total Network receive",
            "# TYPE node_network_receive_bytes_total counter",
            "# HELP node_network_transmit_bytes_total Network transmit",
            "# TYPE node_network_transmit_bytes_total counter",
        ]
        for name, rx, tx in net:
            lines.append(
                f'node_network_receive_bytes_total{{device="{name}"}} {rx}'
            )
            lines.append(
                f'node_network_transmit_bytes_total{{device="{name}"}} {tx}'
            )

    temp = _read_temp_c()
    if temp is not None:
        lines += [
            "# HELP node_hwmon_temp_celsius Hardware temperature",
            "# TYPE node_hwmon_temp_celsius gauge",
            f'node_hwmon_temp_celsius{{chip="thermal_zone0"}} {temp:.3f}',
        ]

    return lines


@dataclass
class AgentMetrics:
    started_at: float = field(default_factory=time.time)
    mqtt_up: bool = False
    broker: MosquittoSupervisor | None = None
    decrypt_worker: DecryptWorker | None = None
    shipper: LokiShipper | None = None

    def _app_up(self) -> dict[str, bool]:
        decrypt_up = bool(self.decrypt_worker and self.decrypt_worker.alive)
        shipper_up = bool(self.shipper and self.shipper.alive)
        mqtt_up = bool(self.mqtt_up)
        if self.broker is not None:
            mqtt_up = bool(self.broker.running())
            self.mqtt_up = mqtt_up
        return {
            "agent": True,
            "mqtt": mqtt_up,
            "decrypt": decrypt_up,
            "shipper": shipper_up,
        }

    def _app_pids(self) -> dict[str, int]:
        pids: dict[str, int] = {"agent": os.getpid()}
        if self.broker is not None:
            mqtt_pid = self.broker.pid
            if mqtt_pid is not None:
                pids["mqtt"] = mqtt_pid
        return pids

    def render(self) -> str:
        uptime = time.time() - self.started_at
        ok = self.decrypt_worker.messages_ok if self.decrypt_worker else 0
        fail = self.decrypt_worker.messages_fail if self.decrypt_worker else 0
        sent = self.shipper.lines_sent if self.shipper else 0
        apps = self._app_up()
        lines = [
            "# HELP iotgw_agent_up Agent process up",
            "# TYPE iotgw_agent_up gauge",
            "iotgw_agent_up 1",
            "# HELP iotgw_agent_uptime_seconds Uptime",
            "# TYPE iotgw_agent_uptime_seconds gauge",
            f"iotgw_agent_uptime_seconds {uptime:.3f}",
            "# HELP iotgw_mqtt_up Mosquitto child running",
            "# TYPE iotgw_mqtt_up gauge",
            f"iotgw_mqtt_up {1 if apps['mqtt'] else 0}",
            "# HELP iotgw_app_up Gateway application / worker up (1=up)",
            "# TYPE iotgw_app_up gauge",
        ]
        for name, is_up in apps.items():
            lines.append(f'iotgw_app_up{{app="{name}"}} {1 if is_up else 0}')

        lines += [
            "# HELP iotgw_decrypt_messages_total Decrypted messages",
            "# TYPE iotgw_decrypt_messages_total counter",
            f'iotgw_decrypt_messages_total{{result="ok"}} {ok}',
            f'iotgw_decrypt_messages_total{{result="fail"}} {fail}',
            "# HELP iotgw_loki_lines_sent_total Lines shipped to Loki",
            "# TYPE iotgw_loki_lines_sent_total counter",
            f"iotgw_loki_lines_sent_total {sent}",
        ]

        pids = self._app_pids()
        cpu_lines: list[str] = []
        mem_lines: list[str] = []
        for app, pid in pids.items():
            cpu = _read_proc_cpu_seconds(pid)
            if cpu is not None:
                cpu_lines.append(f'iotgw_app_cpu_seconds_total{{app="{app}"}} {cpu:.6f}')
            rss = _read_proc_rss_bytes(pid)
            if rss is not None:
                mem_lines.append(f'iotgw_app_memory_bytes{{app="{app}"}} {rss}')
        if cpu_lines:
            lines += [
                "# HELP iotgw_app_cpu_seconds_total Cumulative process CPU time",
                "# TYPE iotgw_app_cpu_seconds_total counter",
                *cpu_lines,
            ]
        if mem_lines:
            lines += [
                "# HELP iotgw_app_memory_bytes Process resident memory",
                "# TYPE iotgw_app_memory_bytes gauge",
                *mem_lines,
            ]

        lines.extend(_host_metric_lines())
        lines.append("")
        return "\n".join(lines)
