"""Behavioral anomaly rules derived from production gateway logs."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from typing import Deque, Dict, List, Optional, Set, Tuple
import time

from .gateway_state import GatewayState
from .log_capture import DeniedEventStats, HaproxySslStats, MqttConnectStats
from .records import PacketRecord
from .utils import safe_float


@dataclass
class RuleViolation:
    device_id: str
    src_ip: str
    violation_type: str
    message: str
    timestamp: datetime = field(default_factory=datetime.now)
    severity: str = "warning"


@dataclass
class DeviceLogContext:
    denied: Optional[DeniedEventStats] = None
    mqtt_connect: Optional[MqttConnectStats] = None
    ssl_stats: Optional[HaproxySslStats] = None


class RuleEngine:
    """Detects behavioral anomalies on accepted gateway traffic."""

    def __init__(self, behavioral_config: Optional[dict] = None) -> None:
        self.config = behavioral_config or {}
        self.enabled = bool(self.config.get("enabled", True))
        self.violations: List[RuleViolation] = []

        self._denied_window_seconds = int(self.config.get("payload_reject_window_seconds", 60))
        self._ratio_window_seconds = int(self.config.get("ratio_window_seconds", 60))
        self._alert_cooldown_seconds = int(self.config.get("alert_cooldown_seconds", 60))

        self._denied_history: Dict[str, Deque[Tuple[float, int]]] = {}
        self._undersize_history: Dict[str, Deque[Tuple[float, int]]] = {}
        self._accepted_history: Dict[str, Deque[Tuple[float, int]]] = {}
        self._consecutive_denied: Dict[str, int] = {}
        self._device_ips: Dict[str, Set[str]] = {}
        self._alert_cooldown_until: Dict[str, Dict[str, float]] = {}

        expected_ips = self.config.get("expected_source_ips", {}) or {}
        self._static_expected_ips: Dict[str, str] = {
            str(device_id): str(ip) for device_id, ip in expected_ips.items()
        }
        self._gateway_state = GatewayState()
        self._enforce_allowed_ips = bool(self.config.get("enforce_allowed_ips", True))
        self._enforce_acl_users = bool(self.config.get("enforce_acl_users", True))
        self._ignored_acl_users = {
            str(user)
            for user in (self.config.get("ignored_acl_users") or ["nodered", "anonymous"])
        }
        self._expected_payload_sizes = {
            int(size)
            for size in (self.config.get("expected_payload_sizes") or [2769, 2793])
        }
        self._undersize_payload_threshold = int(
            self.config.get("undersize_payload_threshold", 2500)
        )

    def update_gateway_state(self, state: GatewayState) -> None:
        self._gateway_state = state

    def _append_history(
        self,
        store: Dict[str, Deque[Tuple[float, int]]],
        device_id: str,
        count: int,
        window_seconds: int,
    ) -> None:
        if count <= 0:
            return
        now = time.time()
        history = store.setdefault(device_id, deque())
        history.append((now, count))
        cutoff = now - window_seconds
        while history and history[0][0] < cutoff:
            history.popleft()

    def _history_total(
        self,
        store: Dict[str, Deque[Tuple[float, int]]],
        device_id: str,
        window_seconds: int,
    ) -> int:
        now = time.time()
        history = store.get(device_id)
        if not history:
            return 0
        cutoff = now - window_seconds
        while history and history[0][0] < cutoff:
            history.popleft()
        return sum(count for _ts, count in history)

    def ingest_denied_counts(self, denied_counts: Dict[str, DeniedEventStats]) -> None:
        for device_id, stats in denied_counts.items():
            if stats.total <= 0:
                continue
            self._append_history(
                self._denied_history, device_id, stats.total, self._denied_window_seconds
            )
            if stats.undersize_count > 0:
                self._append_history(
                    self._undersize_history,
                    device_id,
                    stats.undersize_count,
                    self._denied_window_seconds,
                )
            self._consecutive_denied[device_id] = (
                self._consecutive_denied.get(device_id, 0) + stats.total
            )

    def ingest_accepted(self, device_id: str, count: int = 1) -> None:
        if count <= 0:
            return
        self._consecutive_denied[device_id] = 0
        self._append_history(
            self._accepted_history, device_id, count, self._ratio_window_seconds
        )

    def _denied_total(self, device_id: str) -> int:
        return self._history_total(
            self._denied_history, device_id, self._denied_window_seconds
        )

    def _deny_accept_ratio(self, device_id: str) -> float:
        denied = self._history_total(
            self._denied_history, device_id, self._ratio_window_seconds
        )
        accepted = self._history_total(
            self._accepted_history, device_id, self._ratio_window_seconds
        )
        total = denied + accepted
        if total <= 0:
            return 0.0
        return denied / total

    def _undersize_total(self, device_id: str) -> int:
        return self._history_total(
            self._undersize_history, device_id, self._denied_window_seconds
        )

    def _on_cooldown(self, device_id: str, violation_type: str) -> bool:
        until = self._alert_cooldown_until.get(device_id, {}).get(violation_type, 0.0)
        return time.time() < until

    def _set_cooldown(self, device_id: str, violation_type: str) -> None:
        self._alert_cooldown_until.setdefault(device_id, {})[violation_type] = (
            time.time() + self._alert_cooldown_seconds
        )

    def _reject(
        self,
        device_id: str,
        src_ip: str,
        violation_type: str,
        message: str,
        severity: str = "warning",
    ) -> tuple[bool, Optional[RuleViolation]]:
        if self._on_cooldown(device_id, violation_type):
            return True, None
        violation = RuleViolation(
            device_id=device_id,
            src_ip=src_ip,
            violation_type=violation_type,
            message=message,
            severity=severity,
        )
        self.violations.append(violation)
        self._set_cooldown(device_id, violation_type)
        return False, violation

    def _mean_inter_arrival_ms(self, records: List[PacketRecord]) -> float:
        timestamps = sorted(safe_float(getattr(r, "ts", 0.0), 0.0) for r in records)
        if len(timestamps) < 2:
            return float("inf")
        deltas = [
            max((t2 - t1) * 1000.0, 0.0)
            for t1, t2 in zip(timestamps[:-1], timestamps[1:])
        ]
        return sum(deltas) / len(deltas)

    def _min_inter_arrival_ms(self, records: List[PacketRecord]) -> float:
        timestamps = sorted(safe_float(getattr(r, "ts", 0.0), 0.0) for r in records)
        if len(timestamps) < 2:
            return float("inf")
        return min(max((t2 - t1) * 1000.0, 0.0) for t1, t2 in zip(timestamps[:-1], timestamps[1:]))

    def _message_rate(self, records: List[PacketRecord]) -> float:
        if len(records) < 2:
            return float(len(records))
        timestamps = sorted(safe_float(getattr(r, "ts", 0.0), 0.0) for r in records)
        span = max(timestamps[-1] - timestamps[0], 0.001)
        return len(records) / span

    def _payload_size_bytes(self, record: PacketRecord) -> int:
        extra = getattr(record, "extra", None) or {}
        size = int(safe_float(extra.get("payload_size_bytes", 0), 0.0))
        if size > 0:
            return size
        return int(getattr(record, "pkt_len", 0) or 0)

    def _evaluate_denied_signals(
        self,
        device_id: str,
        src_ip: str,
        context: DeviceLogContext,
    ) -> tuple[bool, Optional[RuleViolation]]:
        deny_ratio = self._deny_accept_ratio(device_id)
        deny_ratio_threshold = float(self.config.get("deny_accept_ratio_threshold", 0.10))
        if deny_ratio > deny_ratio_threshold:
            return self._reject(
                device_id,
                src_ip,
                "deny_accept_ratio",
                (
                    f"Device {device_id} denied/accept ratio {deny_ratio:.1%} exceeds "
                    f"threshold {deny_ratio_threshold:.1%} in {self._ratio_window_seconds}s"
                ),
                severity="critical",
            )

        undersize_threshold = int(self.config.get("undersize_payload_campaign_threshold", 3))
        undersize_total = self._undersize_total(device_id)
        if undersize_total >= undersize_threshold:
            return self._reject(
                device_id,
                src_ip,
                "undersize_payload_campaign",
                (
                    f"Device {device_id} logged {undersize_total} undersize "
                    f"(<{self._undersize_payload_threshold} B) denied payloads in "
                    f"{self._denied_window_seconds}s"
                ),
                severity="critical",
            )

        probe_threshold = int(self.config.get("denied_probe_burst_threshold", 5))
        consecutive_denied = self._consecutive_denied.get(device_id, 0)
        if consecutive_denied >= probe_threshold:
            return self._reject(
                device_id,
                src_ip,
                "denied_probe_burst",
                (
                    f"Device {device_id} has {consecutive_denied} consecutive "
                    f"denied events without accepted traffic (threshold {probe_threshold})"
                ),
                severity="warning",
            )

        denied_total = self._denied_total(device_id)
        denied_threshold = int(self.config.get("payload_reject_storm_threshold", 5))
        if denied_total >= denied_threshold:
            return self._reject(
                device_id,
                src_ip,
                "payload_reject_storm",
                (
                    f"Device {device_id} accumulated {denied_total} "
                    f"Node-RED payload rejections (threshold {denied_threshold})"
                ),
                severity="critical",
            )

        if context.ssl_stats is not None:
            ssl_threshold = int(self.config.get("ssl_handshake_storm_threshold", 10))
            if context.ssl_stats.failure_count >= ssl_threshold:
                return self._reject(
                    device_id,
                    src_ip,
                    "ssl_handshake_storm",
                    (
                        f"Source IP {src_ip} triggered {context.ssl_stats.failure_count} "
                        f"HAProxy SSL handshake failures in "
                        f"{int(context.ssl_stats.window_seconds)}s (threshold {ssl_threshold})"
                    ),
                    severity="warning",
                )

        if context.mqtt_connect is not None and context.ssl_stats is not None:
            triad_enabled = bool(self.config.get("attack_triad_enabled", True))
            if triad_enabled:
                cp_ratio = context.mqtt_connect.connect_publish_ratio
                ssl_threshold = int(self.config.get("ssl_handshake_storm_threshold", 10))
                triad_cp = float(self.config.get("attack_triad_connect_publish_ratio", 1.15))
                triad_deny = float(self.config.get("attack_triad_deny_ratio", 0.10))
                if (
                    deny_ratio > triad_deny
                    and context.mqtt_connect.publish_count > 0
                    and cp_ratio > triad_cp
                    and context.ssl_stats.failure_count >= ssl_threshold
                ):
                    return self._reject(
                        device_id,
                        src_ip,
                        "attack_triad",
                        (
                            f"Coordinated attack indicators on {device_id}: "
                            f"deny_ratio={deny_ratio:.1%}, "
                            f"connect/publish={cp_ratio:.2f}, "
                            f"ssl_failures={context.ssl_stats.failure_count}"
                        ),
                        severity="critical",
                    )

        return True, None

    def evaluate(
        self,
        device_id: str,
        src_ip: str,
        records: List[PacketRecord],
        context: Optional[DeviceLogContext] = None,
    ) -> tuple[bool, Optional[RuleViolation]]:
        if not self.enabled:
            return True, None

        context = context or DeviceLogContext()
        if not records:
            return self._evaluate_denied_signals(device_id, src_ip, context)

        self.ingest_accepted(device_id, count=len(records))

        if (
            self._enforce_acl_users
            and self._gateway_state.acl_users
            and device_id not in self._ignored_acl_users
            and not self._gateway_state.is_acl_user(device_id)
        ):
            return self._reject(
                device_id,
                src_ip,
                "unknown_acl_user",
                (
                    f"Device {device_id} is not present in the current Mosquitto ACL "
                    f"({sorted(self._gateway_state.acl_users)})"
                ),
                severity="critical",
            )

        if (
            self._enforce_allowed_ips
            and src_ip
            and self._gateway_state.allowed_ips
            and not self._gateway_state.is_ip_allowed(src_ip)
        ):
            return self._reject(
                device_id,
                src_ip,
                "source_ip_not_allowed",
                (
                    f"Accepted traffic from {src_ip} is outside the gateway "
                    f"allowed IP set {sorted(self._gateway_state.allowed_ips)}"
                ),
                severity="critical",
            )

        if (
            self._gateway_state.device_source_ips
            and device_id not in self._ignored_acl_users
            and device_id not in self._gateway_state.device_source_ips
        ):
            return self._reject(
                device_id,
                src_ip,
                "inactive_sensor_traffic",
                (
                    f"Accepted traffic from {device_id} but device is not in "
                    f"active sensors ({sorted(self._gateway_state.device_source_ips)})"
                ),
                severity="warning",
            )

        if context.ssl_stats is not None:
            ssl_threshold = int(self.config.get("ssl_handshake_storm_threshold", 10))
            if context.ssl_stats.failure_count >= ssl_threshold:
                return self._reject(
                    device_id,
                    src_ip,
                    "ssl_handshake_storm",
                    (
                        f"Source IP {src_ip} triggered {context.ssl_stats.failure_count} "
                        f"HAProxy SSL handshake failures in "
                        f"{int(context.ssl_stats.window_seconds)}s (threshold {ssl_threshold})"
                    ),
                    severity="warning",
                )

        denied_only = self._evaluate_denied_signals(device_id, src_ip, context)
        if not denied_only[0]:
            return denied_only

        expected_ip = (
            self._static_expected_ips.get(device_id)
            or self._gateway_state.expected_ip_for(device_id)
        )
        if expected_ip and src_ip and src_ip != expected_ip:
            return self._reject(
                device_id,
                src_ip,
                "source_ip_baseline",
                (
                    f"Device {device_id} accepted traffic from {src_ip}, "
                    f"expected baseline {expected_ip}"
                ),
                severity="critical",
            )

        for record in records:
            payload_size = self._payload_size_bytes(record)
            if (
                payload_size > 0
                and self._expected_payload_sizes
                and payload_size not in self._expected_payload_sizes
            ):
                return self._reject(
                    device_id,
                    src_ip,
                    "accepted_size_drift",
                    (
                        f"Device {device_id} accepted payload size {payload_size} bytes "
                        f"outside expected {sorted(self._expected_payload_sizes)}"
                    ),
                    severity="warning",
                )

        max_skew = float(self.config.get("max_clock_skew_seconds", 2.5))
        for record in records:
            delay = safe_float(getattr(record, "mqtt_delay", 0.0), 0.0)
            if delay < 0:
                return self._reject(
                    device_id,
                    src_ip,
                    "future_timestamp",
                    (
                        f"Device {device_id} reported timestamp {abs(delay):.3f}s "
                        f"ahead of gateway receive time (possible replay)"
                    ),
                    severity="warning",
                )
            if delay > max_skew:
                return self._reject(
                    device_id,
                    src_ip,
                    "clock_skew_anomaly",
                    (
                        f"Device {device_id} clock skew {delay:.3f}s "
                        f"exceeds {max_skew:.3f}s (possible replay)"
                    ),
                    severity="warning",
                )

        min_rate = float(self.config.get("max_message_rate_per_sec", 1.5))
        rate = self._message_rate(records)
        if len(records) >= 2 and rate > min_rate:
            return self._reject(
                device_id,
                src_ip,
                "high_message_rate",
                (
                    f"Device {device_id} rate {rate:.2f} msg/s exceeds "
                    f"baseline threshold {min_rate:.2f} msg/s"
                ),
                severity="warning",
            )

        accelerated_ms = float(self.config.get("min_inter_arrival_baseline_ms", 900.0))
        if len(records) >= 2 and self._min_inter_arrival_ms(records) < accelerated_ms:
            return self._reject(
                device_id,
                src_ip,
                "accelerated_publishing",
                (
                    f"Device {device_id} min inter-arrival "
                    f"{self._min_inter_arrival_ms(records):.0f}ms below "
                    f"benign baseline {accelerated_ms:.0f}ms"
                ),
                severity="warning",
            )

        min_iat_ms = float(self.config.get("min_inter_arrival_ms", 80.0))
        mean_iat = self._mean_inter_arrival_ms(records)
        if len(records) >= int(self.config.get("rapid_fire_min_messages", 3)) and mean_iat < min_iat_ms:
            return self._reject(
                device_id,
                src_ip,
                "rapid_fire",
                (
                    f"Device {device_id} mean inter-arrival {mean_iat:.1f}ms "
                    f"below threshold {min_iat_ms:.1f}ms"
                ),
                severity="warning",
            )

        if context.mqtt_connect is not None:
            max_connect_rate = float(self.config.get("max_mqtt_connect_rate", 1.5))
            min_connect_count = int(self.config.get("min_mqtt_connect_count", 10))
            if context.mqtt_connect.connect_rate > max_connect_rate:
                return self._reject(
                    device_id,
                    src_ip,
                    "mqtt_connect_churn",
                    (
                        f"Device {device_id} MQTT connect rate "
                        f"{context.mqtt_connect.connect_rate:.2f}/s exceeds "
                        f"benign baseline {max_connect_rate:.2f}/s"
                    ),
                    severity="warning",
                )
            if context.mqtt_connect.connect_count >= min_connect_count:
                return self._reject(
                    device_id,
                    src_ip,
                    "mqtt_connect_churn",
                    (
                        f"Device {device_id} logged {context.mqtt_connect.connect_count} "
                        f"MQTT connects in {int(context.mqtt_connect.window_seconds)}s "
                        f"(threshold {min_connect_count})"
                    ),
                    severity="warning",
                )

            max_cp_ratio = float(self.config.get("max_connect_publish_ratio", 1.15))
            cp_ratio = context.mqtt_connect.connect_publish_ratio
            if (
                context.mqtt_connect.publish_count > 0
                and cp_ratio > max_cp_ratio
            ):
                return self._reject(
                    device_id,
                    src_ip,
                    "connect_publish_ratio",
                    (
                        f"Device {device_id} MQTT connect/publish ratio {cp_ratio:.2f} "
                        f"exceeds benign baseline {max_cp_ratio:.2f}"
                    ),
                    severity="warning",
                )

            client_multiplier = float(
                self.config.get("ephemeral_client_multiplier", 1.25)
            )
            publish_count = max(context.mqtt_connect.publish_count, 1)
            unique_clients = len(context.mqtt_connect.unique_client_ids)
            if unique_clients > publish_count * client_multiplier:
                return self._reject(
                    device_id,
                    src_ip,
                    "ephemeral_client_churn",
                    (
                        f"Device {device_id} used {unique_clients} ephemeral client IDs "
                        f"vs {context.mqtt_connect.publish_count} publishes in "
                        f"{int(context.mqtt_connect.window_seconds)}s"
                    ),
                    severity="warning",
                )

            if len(context.mqtt_connect.unique_ips) > 1:
                return self._reject(
                    device_id,
                    src_ip,
                    "mqtt_multi_ip_connect",
                    (
                        f"Device {device_id} MQTT connects from multiple IPs: "
                        f"{sorted(context.mqtt_connect.unique_ips)}"
                    ),
                    severity="critical",
                )

        known_ips = self._device_ips.setdefault(device_id, set())
        if src_ip:
            known_ips.add(src_ip)
        if len(known_ips) > 1:
            return self._reject(
                device_id,
                src_ip,
                "cross_ip_identity",
                (
                    f"Device {device_id} accepted traffic from multiple IPs: "
                    f"{sorted(known_ips)}"
                ),
                severity="critical",
            )

        triad_enabled = bool(self.config.get("attack_triad_enabled", True))
        if triad_enabled and context.mqtt_connect is not None and context.ssl_stats is not None:
            deny_ratio = self._deny_accept_ratio(device_id)
            cp_ratio = context.mqtt_connect.connect_publish_ratio
            ssl_threshold = int(self.config.get("ssl_handshake_storm_threshold", 10))
            triad_cp = float(self.config.get("attack_triad_connect_publish_ratio", 1.15))
            triad_deny = float(self.config.get("attack_triad_deny_ratio", 0.10))
            if (
                deny_ratio > triad_deny
                and context.mqtt_connect.publish_count > 0
                and cp_ratio > triad_cp
                and context.ssl_stats.failure_count >= ssl_threshold
            ):
                return self._reject(
                    device_id,
                    src_ip,
                    "attack_triad",
                    (
                        f"Coordinated attack indicators on {device_id}: "
                        f"deny_ratio={deny_ratio:.1%}, "
                        f"connect/publish={cp_ratio:.2f}, "
                        f"ssl_failures={context.ssl_stats.failure_count}"
                    ),
                    severity="critical",
                )

        return True, None

    def get_violations(self, device_id: Optional[str] = None) -> List[RuleViolation]:
        if device_id:
            return [v for v in self.violations if v.device_id == device_id]
        return self.violations

    def clear_violations(self) -> None:
        self.violations.clear()