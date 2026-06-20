from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .features import build_feature_vector, empty_feature_vector
from .model import IDSModel
from .records import PacketRecord
from .rules import RuleEngine, RuleViolation

_MQTT_PORTS: frozenset[int] = frozenset({1883, 18883, 8883})


@dataclass
class DetectionResult:
    src_ip: str
    attack_probability: float
    is_attack: bool
    features: Dict[str, float]
    predicted_class: str = ""
    family_probability: float = 0.0
    raw_probabilities: list[float] | None = None
    rule_passed: bool = True
    rule_violation: Optional[RuleViolation] = None
    skipped_reason: str = ""
    semantic_risk: str = "LOW"
    risk_flags: list[str] = field(default_factory=list)
    ml_trustworthy: bool = True


class Detector:
    def __init__(
        self,
        model: IDSModel,
        threshold: float,
        rule_engine: Optional[RuleEngine] = None,
        min_packets_per_window: int = 3,
        semantic_guard: Optional[dict] = None,
    ) -> None:
        self.model = model
        self.threshold = threshold
        self.rule_engine = rule_engine or RuleEngine()
        self.min_packets_per_window = max(int(min_packets_per_window), 1)
        self.semantic_guard = semantic_guard or {}

    def _semantic_assessment(
        self,
        records: List[PacketRecord],
        features: Dict[str, float],
    ) -> tuple[str, list[str], bool]:
        if not records:
            return "HIGH", ["empty_window"], False

        if not self.semantic_guard.get("enabled", True):
            return "LOW", [], True

        risk_flags: list[str] = []

        all_tcp = all(r.proto == "TCP" for r in records)
        all_same_mqtt_port = all(
            (r.src_port in _MQTT_PORTS or r.dst_port in _MQTT_PORTS) for r in records
        )
        has_any_tcp_flags = any(bool(r.tcp_flags) for r in records)
        all_mqtt_topics = all(bool(r.mqtt_topic) for r in records)
        any_fallback = any(
            getattr(r, "capture_mode", "sensor_log") == "mqtt_fallback" for r in records
        )
        any_low_quality = any(
            getattr(r, "semantic_quality", "HIGH") == "LOW" for r in records
        )

        if any_fallback:
            risk_flags.append("mqtt_fallback_records")
        if any_low_quality:
            risk_flags.append("low_quality_records")
        if all_tcp and all_same_mqtt_port and all_mqtt_topics:
            risk_flags.append("single_mqtt_port_only")
        if all_tcp and not has_any_tcp_flags:
            risk_flags.append("no_tcp_flags_available")
        if (
            self.semantic_guard.get("require_real_tcp_flags_for_mqtt_topics", True)
            and all_mqtt_topics
            and not has_any_tcp_flags
        ):
            risk_flags.append("mqtt_topics_without_real_flags")

        if any_fallback or any_low_quality or "mqtt_topics_without_real_flags" in risk_flags:
            return "HIGH", risk_flags, False

        if risk_flags:
            return "MEDIUM", risk_flags, True

        return "LOW", risk_flags, True

    def evaluate_host(
        self,
        src_ip: str,
        records: List[PacketRecord],
        src_mac: Optional[str] = None,
        token: Optional[str] = None,
    ) -> DetectionResult:
        pkt_count = len(records)
        rule_passed, violation = self.rule_engine.evaluate(
            src_ip=src_ip, src_mac=src_mac, token=token, pkt_count=pkt_count,
        )
        if not rule_passed:
            return DetectionResult(
                src_ip=src_ip,
                attack_probability=0.0,
                is_attack=False,
                features=empty_feature_vector(),
                rule_passed=False,
                rule_violation=violation,
            )

        features = build_feature_vector(records)
        semantic_risk, risk_flags, ml_trustworthy = self._semantic_assessment(records, features)

        if pkt_count < self.min_packets_per_window:
            return DetectionResult(
                src_ip=src_ip,
                attack_probability=0.0,
                is_attack=False,
                features=features,
                rule_passed=True,
                skipped_reason=f"insufficient_packets<{self.min_packets_per_window}",
                semantic_risk=semantic_risk,
                risk_flags=risk_flags,
                ml_trustworthy=ml_trustworthy,
            )

        score = self.model.predict_attack_probability(features)
        print(f"[IDS-DEBUG] src={src_ip} features={features} score={score:.6f}")

        if not ml_trustworthy:
            return DetectionResult(
                src_ip=src_ip,
                attack_probability=score,
                is_attack=False,
                features=features,
                rule_passed=True,
                skipped_reason="semantic_guard_high_risk",
                semantic_risk=semantic_risk,
                risk_flags=risk_flags,
                ml_trustworthy=False,
            )

        return DetectionResult(
            src_ip=src_ip,
            attack_probability=score,
            is_attack=(score >= self.threshold),
            features=features,
            rule_passed=True,
            semantic_risk=semantic_risk,
            risk_flags=risk_flags,
            ml_trustworthy=True,
        )

    def evaluate_batch(
        self,
        batches: Dict[str, List[PacketRecord]],
        src_macs: Optional[Dict[str, str]] = None,
        tokens: Optional[Dict[str, str]] = None,
    ) -> List[DetectionResult]:
        results: List[DetectionResult] = []
        src_macs = src_macs or {}
        tokens = tokens or {}
        for src_ip, records in batches.items():
            results.append(
                self.evaluate_host(
                    src_ip, records,
                    src_mac=src_macs.get(src_ip),
                    token=tokens.get(src_ip),
                )
            )
        return results