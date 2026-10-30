"""Prometheus text exposition for the monolithic agent (incl. node_* compat)."""

from __future__ import annotations

import os
import socket
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from .broker import MosquittoSupervisor
    from .decrypt_worker import DecryptWorker
    from .denied_watcher import DeniedWatcher
    from .kafka_producer import SensorKafkaProducer
    from .shipper import LokiShipper

_MOSQUITTO_PID_FILES = (
    Path("/run/mosquitto/mosquitto.pid"),
    Path("/var/run/mosquitto/mosquitto.pid"),
    Path("/run/mosquitto.pid"),
    Path("/var/run/mosquitto.pid"),
)


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


def tcp_open(host: str, port: int, *, timeout: float = 0.4) -> bool:
    """True when a TCP connect to host:port succeeds."""
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return True
    except OSError:
        return False


def find_mosquitto_pid() -> Optional[int]:
    """Best-effort PID for a system or child mosquitto process."""
    for path in _MOSQUITTO_PID_FILES:
        try:
            pid = int(path.read_text(encoding="utf-8").strip().split()[0])
        except (OSError, ValueError, IndexError):
            continue
        if pid > 1 and Path(f"/proc/{pid}").exists():
            return pid
    try:
        for entry in Path("/proc").iterdir():
            if not entry.name.isdigit():
                continue
            try:
                raw = (entry / "cmdline").read_bytes()
            except OSError:
                continue
            cmd = raw.replace(b"\x00", b" ").decode("utf-8", errors="ignore")
            if "mosquitto" in cmd and "iot-gateway-agent" not in cmd:
                return int(entry.name)
    except OSError:
        pass
    return None


def find_kafka_pid() -> Optional[int]:
    """Best-effort PID for the local KRaft Kafka JVM (iotgw-kafka)."""
    candidates = (
        Path("/run/iotgw-kafka.pid"),
        Path("/var/run/iotgw-kafka.pid"),
    )
    for path in candidates:
        try:
            pid = int(path.read_text(encoding="utf-8").strip().split()[0])
        except (OSError, ValueError, IndexError):
            continue
        if pid > 1 and Path(f"/proc/{pid}").exists():
            return pid
    try:
        for entry in Path("/proc").iterdir():
            if not entry.name.isdigit():
                continue
            try:
                raw = (entry / "cmdline").read_bytes()
            except OSError:
                continue
            cmd = raw.replace(b"\x00", b" ").decode("utf-8", errors="ignore").lower()
            # Official Kafka start scripts: java … kafka.Kafka / kraft
            if "java" in cmd and (
                "kafka.kafka" in cmd
                or "kafka.raft" in cmd
                or "/opt/kafka/" in cmd
                or "iotgw.properties" in cmd
            ):
                return int(entry.name)
    except OSError:
        pass
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


# Avoid scrape stampedes: Prometheus scrape_timeout is 5–10s; if render ever
# stalls, overlapping /metrics handlers peg the Pi and Gateway Metric shows
# "no scrape". Serve a short-lived cached body under a single flight lock.
_METRICS_CACHE_TTL_S = 1.0


@dataclass
class AgentMetrics:
    started_at: float = field(default_factory=time.time)
    mqtt_up: bool = False
    mqtt_port: int = 1883
    mqtt_host: str = "127.0.0.1"
    kafka_bootstrap: str = "127.0.0.1:9092"
    broker: MosquittoSupervisor | None = None
    decrypt_worker: DecryptWorker | None = None
    shipper: LokiShipper | None = None
    kafka: SensorKafkaProducer | None = None
    denied_watcher: DeniedWatcher | None = None
    _render_lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    _cached_body: str = field(default="", repr=False)
    _cached_at: float = field(default=0.0, repr=False)

    def refresh_mqtt_up(self) -> bool:
        """Child broker running, or system/external broker accepting TCP."""
        child_up = bool(self.broker is not None and self.broker.running())
        if child_up:
            self.mqtt_up = True
            return True
        self.mqtt_up = tcp_open(self.mqtt_host, self.mqtt_port)
        return self.mqtt_up

    def refresh_kafka_up(self) -> bool:
        if self.kafka is not None and self.kafka.up:
            return True
        host, _, port_s = self.kafka_bootstrap.partition(":")
        try:
            port = int(port_s or "9092")
        except ValueError:
            port = 9092
        return tcp_open(host or "127.0.0.1", port)

    def _app_up(self) -> dict[str, bool]:
        decrypt_up = bool(self.decrypt_worker and self.decrypt_worker.alive)
        shipper_up = bool(self.shipper and self.shipper.alive)
        mqtt_up = self.refresh_mqtt_up()
        kafka_up = self.refresh_kafka_up()
        return {
            "agent": True,
            "mqtt": mqtt_up,
            "decrypt": decrypt_up,
            "shipper": shipper_up,
            "kafka": kafka_up,
        }

    def _app_pids(self) -> dict[str, int]:
        pids: dict[str, int] = {"agent": os.getpid()}
        mqtt_pid: Optional[int] = None
        if self.broker is not None:
            mqtt_pid = self.broker.pid
        if mqtt_pid is None:
            mqtt_pid = find_mosquitto_pid()
        if mqtt_pid is not None:
            pids["mqtt"] = mqtt_pid
        kafka_pid = find_kafka_pid()
        if kafka_pid is not None:
            pids["kafka"] = kafka_pid
        return pids

    def render(self) -> str:
        """Prometheus text; cached briefly so concurrent scrapes share one render."""
        now = time.time()
        with self._render_lock:
            if self._cached_body and (now - self._cached_at) < _METRICS_CACHE_TTL_S:
                return self._cached_body
            body = self._render_uncached()
            self._cached_body = body
            self._cached_at = now
            return body

    def _render_uncached(self) -> str:
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
            "# HELP iotgw_mqtt_up MQTT broker reachable (child or system)",
            "# TYPE iotgw_mqtt_up gauge",
            f"iotgw_mqtt_up {1 if apps['mqtt'] else 0}",
            "# HELP iotgw_app_up Gateway application / worker up (1=up)",
            "# TYPE iotgw_app_up gauge",
        ]
        for name, is_up in apps.items():
            lines.append(f'iotgw_app_up{{app="{name}"}} {1 if is_up else 0}')

        env_ok = getattr(self.decrypt_worker, "envelope_ok", 0) if self.decrypt_worker else 0
        env_fail = (
            getattr(self.decrypt_worker, "envelope_fail", 0) if self.decrypt_worker else 0
        )
        legacy_ok = (
            getattr(self.decrypt_worker, "legacy_ok", 0) if self.decrypt_worker else 0
        )
        lines += [
            "# HELP iotgw_decrypt_messages_total Decrypted messages",
            "# TYPE iotgw_decrypt_messages_total counter",
            f'iotgw_decrypt_messages_total{{result="ok"}} {ok}',
            f'iotgw_decrypt_messages_total{{result="fail"}} {fail}',
            "# HELP iotgw_envelope_messages_total Envelope v1 decrypt results",
            "# TYPE iotgw_envelope_messages_total counter",
            f'iotgw_envelope_messages_total{{result="ok"}} {env_ok}',
            f'iotgw_envelope_messages_total{{result="fail"}} {env_fail}',
            "# HELP iotgw_legacy_fernet_messages_total Legacy Fernet wrapper accepts",
            "# TYPE iotgw_legacy_fernet_messages_total counter",
            f"iotgw_legacy_fernet_messages_total {legacy_ok}",
            "# HELP iotgw_loki_lines_sent_total Lines shipped to Loki",
            "# TYPE iotgw_loki_lines_sent_total counter",
            f"iotgw_loki_lines_sent_total {sent}",
        ]

        kafka_up = 1 if apps.get("kafka") else 0
        kafka_ok = self.kafka.produced_ok if self.kafka else 0
        kafka_fail = self.kafka.produced_fail if self.kafka else 0
        lines += [
            "# HELP iotgw_kafka_up Local Kafka broker reachable",
            "# TYPE iotgw_kafka_up gauge",
            f"iotgw_kafka_up {kafka_up}",
            "# HELP iotgw_kafka_produce_total Agent Kafka produce attempts",
            "# TYPE iotgw_kafka_produce_total counter",
            f'iotgw_kafka_produce_total{{result="ok"}} {kafka_ok}',
            f'iotgw_kafka_produce_total{{result="fail"}} {kafka_fail}',
        ]

        denied_total = self.denied_watcher.denied_total if self.denied_watcher else 0
        ids_total = self.denied_watcher.ids_total if self.denied_watcher else 0
        # Prefer summed per-device counters when watcher totals are zero but worker bumped.
        by_device = (
            self.decrypt_worker.device_snapshot() if self.decrypt_worker else {}
        )
        if by_device:
            denied_total = max(
                denied_total, sum(c.denied for c in by_device.values())
            )
            ids_total = max(ids_total, sum(c.ids for c in by_device.values()))
        lines += [
            "# HELP iotgw_denied_publishes_total Mosquitto Denied PUBLISH events",
            "# TYPE iotgw_denied_publishes_total counter",
            f"iotgw_denied_publishes_total {denied_total}",
            "# HELP iotgw_ids_detections_total IDS / anomaly detections",
            "# TYPE iotgw_ids_detections_total counter",
            f"iotgw_ids_detections_total {ids_total}",
        ]

        if by_device:
            from .kafka_store import kafka_topic_name

            lines += [
                "# HELP iotgw_device_messages_total Per-device decrypted messages",
                "# TYPE iotgw_device_messages_total counter",
            ]
            for did, ctr in sorted(by_device.items()):
                topic = kafka_topic_name(did)
                lines.append(
                    f'iotgw_device_messages_total{{device_id="{did}",'
                    f'kafka_topic="{topic}",result="ok"}} {ctr.messages_ok}'
                )
                lines.append(
                    f'iotgw_device_messages_total{{device_id="{did}",'
                    f'kafka_topic="{topic}",result="fail"}} {ctr.messages_fail}'
                )
            lines += [
                "# HELP iotgw_device_denied_publishes_total Per-device denied publishes",
                "# TYPE iotgw_device_denied_publishes_total counter",
            ]
            for did, ctr in sorted(by_device.items()):
                topic = kafka_topic_name(did)
                lines.append(
                    f'iotgw_device_denied_publishes_total{{device_id="{did}",'
                    f'kafka_topic="{topic}"}} {ctr.denied}'
                )
            lines += [
                "# HELP iotgw_device_ids_detections_total Per-device IDS detections",
                "# TYPE iotgw_device_ids_detections_total counter",
            ]
            for did, ctr in sorted(by_device.items()):
                topic = kafka_topic_name(did)
                lines.append(
                    f'iotgw_device_ids_detections_total{{device_id="{did}",'
                    f'kafka_topic="{topic}"}} {ctr.ids}'
                )
            lines += [
                "# HELP iotgw_device_delay_ms Last gateway processing delay "
                "(MQTT receive → Kafka produce, ms)",
                "# TYPE iotgw_device_delay_ms gauge",
            ]
            for did, ctr in sorted(by_device.items()):
                if ctr.last_delay_ms is None:
                    continue
                topic = kafka_topic_name(did)
                lines.append(
                    f'iotgw_device_delay_ms{{device_id="{did}",'
                    f'kafka_topic="{topic}"}} {ctr.last_delay_ms:.3f}'
                )
            lines += [
                "# HELP iotgw_device_delay_ms_sum Cumulative gateway processing "
                "delay (ms)",
                "# TYPE iotgw_device_delay_ms_sum counter",
                "# HELP iotgw_device_delay_samples_total Gateway processing "
                "delay sample count",
                "# TYPE iotgw_device_delay_samples_total counter",
            ]
            for did, ctr in sorted(by_device.items()):
                if ctr.delay_ms_count <= 0:
                    continue
                topic = kafka_topic_name(did)
                lines.append(
                    f'iotgw_device_delay_ms_sum{{device_id="{did}",'
                    f'kafka_topic="{topic}"}} {ctr.delay_ms_sum:.3f}'
                )
                lines.append(
                    f'iotgw_device_delay_samples_total{{device_id="{did}",'
                    f'kafka_topic="{topic}"}} {ctr.delay_ms_count}'
                )

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
