from __future__ import annotations

import argparse
import ipaddress
import time
from collections import defaultdict

from .blocker import IptablesBlocker
from .capture import PacketCapture
from .config import load_config
from .detector import Detector
from .model import IDSModel
from .rules import RuleEngine


INTERNAL_TOPIC_PREFIXES = ("$SYS/",)
SENSOR_TOPIC_PREFIX = "sensors/"


def _device_id_from_topic(topic: str) -> str:
    if not topic:
        return ""
    parts = topic.split("/")
    if len(parts) >= 3 and parts[0] == "sensors":
        return parts[1]
    return ""


def _is_internal_or_loopback_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_loopback or addr.is_multicast or addr.is_unspecified
    except Exception:
        return False


def _is_internal_topic(topic: str) -> bool:
    return any(topic.startswith(prefix) for prefix in INTERNAL_TOPIC_PREFIXES)


def _is_sensor_topic(topic: str) -> bool:
    return topic.startswith(SENSOR_TOPIC_PREFIX)


def _describe_batch(records):
    first_record = None
    for record in records:
        first_record = record
        if record.mqtt_topic or record.mqtt_device_id:
            break
    if first_record is None:
        return "unknown", "unknown", "unknown"
    topic = first_record.mqtt_topic or "unknown"
    device_id = (
        first_record.mqtt_device_id
        or _device_id_from_topic(topic)
        or first_record.src_ip
    )
    observed_src = first_record.observed_src_ip or first_record.src_ip
    return device_id, topic, observed_src


def _split_into_model_windows(records, packet_window_seconds: int):
    if not records:
        return []
    packet_window_seconds = max(int(packet_window_seconds), 1)
    ordered = sorted(records, key=lambda r: (float(r.ts), r.dst_port, r.src_port))
    buckets: dict[int, list] = defaultdict(list)
    for rec in ordered:
        bucket = int(float(rec.ts) // packet_window_seconds)
        buckets[bucket].append(rec)
    return [buckets[k] for k in sorted(buckets)]


def run(config_path: str = "configs/ids_config.yaml") -> None:
    cfg = load_config(config_path)
    gateway_cfg = cfg["gateway"]
    model_cfg = cfg["model"]
    capture_type = str(gateway_cfg.get("capture_type", "pcap") or "pcap").strip().lower()
    use_mac = gateway_cfg.get("mac_tracking", False)
    allow_loopback_sources = bool(gateway_cfg.get("allow_loopback_sources", False))

    if capture_type in {"mqtt", "mqtt_message"}:
        from .mqtt_capture import MQTTCapture
        mqtt_cfg = gateway_cfg.get("mqtt", {})
        capture = MQTTCapture(
            broker=mqtt_cfg.get("broker", "localhost"),
            port=int(mqtt_cfg.get("port", 1883)),
            topic=mqtt_cfg.get("topic", "ids/packets/#"),
            client_id=mqtt_cfg.get("client_id"),
            username=mqtt_cfg.get("username"),
            password=mqtt_cfg.get("password"),
            use_mac=use_mac,
        )
    else:
        bpf_filter = gateway_cfg.get(
            "capture_filter", "tcp port 1883 or tcp port 18883 or tcp port 8883"
        )
        print(f"[IDS] capture BPF filter: {bpf_filter!r}")
        capture = PacketCapture(
            interface=gateway_cfg["capture_interface"], bpf_filter=bpf_filter
        )

    model = IDSModel(
        model_path=model_cfg["path"],
        scaler_path=model_cfg.get("scaler_path"),
        features=model_cfg["expected_features"],
    )

    configured_threshold = gateway_cfg.get("suspicious_threshold")
    if configured_threshold is None:
        configured_threshold = model.get_default_threshold()
        threshold_source = "model_metadata"
    else:
        threshold_source = "config"
    if configured_threshold is None:
        configured_threshold = 0.7
        threshold_source = "default"

    whitelist_path = gateway_cfg.get("device_whitelist_path", "configs/device_whitelist.yaml")
    rule_engine = RuleEngine(device_registry_path=whitelist_path)
    print(f"[IDS] whitelist path: {whitelist_path}")
    print(
        "[IDS] trusted subnets: "
        f"{[str(net) for net in rule_engine.registry.trusted_subnets]}"
    )

    min_model_packets = int(
        gateway_cfg.get("min_model_packets", gateway_cfg.get("min_pkts", 3))
    )
    semantic_guard = gateway_cfg.get("ml_semantic_guard", {})
    detector = Detector(
        model=model,
        threshold=float(configured_threshold),
        rule_engine=rule_engine,
        min_packets_per_window=min_model_packets,
        semantic_guard=semantic_guard,
    )

    packet_window_seconds = int(gateway_cfg.get("packet_window_seconds", 3))
    ip_aggregation_window = int(gateway_cfg.get("ip_aggregation_window", 5))
    min_windows_for_decision = int(gateway_cfg.get("min_windows_for_decision", 3))
    min_attack_windows = int(gateway_cfg.get("min_attack_windows", 2))
    attack_vote_ratio_threshold = float(gateway_cfg.get("attack_vote_ratio_threshold", 0.6))
    ip_avg_score_threshold = float(
        gateway_cfg.get("ip_avg_score_threshold", float(configured_threshold))
    )
    block_on_high_risk = bool(semantic_guard.get("block_on_high_risk", False))

    ip_window_state: dict[str, list[tuple[float, bool]]] = defaultdict(list)
    blocker = IptablesBlocker(block_seconds=gateway_cfg["default_block_seconds"])

    print(f"[IDS] capture type: {capture_type}")
    if capture_type not in {"mqtt", "mqtt_message"}:
        print(f"[IDS] capture interface active: {capture.interface}")
    print(f"[IDS] suspicious threshold: {float(configured_threshold):.6f} ({threshold_source})")
    print(f"[IDS] packet_window_seconds: {packet_window_seconds}")
    print(f"[IDS] min_model_packets: {min_model_packets}")
    print(f"[IDS] semantic_guard: {semantic_guard}")
    print(
        "[IDS] IP aggregation: "
        f"window={ip_aggregation_window} min_windows={min_windows_for_decision} "
        f"min_attack_windows={min_attack_windows} vote_ratio={attack_vote_ratio_threshold:.2f} "
        f"avg_score_threshold={ip_avg_score_threshold:.4f}"
    )
    print("[IDS] Gateway IDS loop started")

    while True:
        packets_by_source = capture.sniff_once(timeout=gateway_cfg["inference_interval_seconds"])
        blocker.unblock_expired()

        for src_key, records in packets_by_source.items():
            windows = _split_into_model_windows(records, packet_window_seconds)
            if not windows:
                print(f"[IDS] skip src={src_key} reason=no_windows")
                continue

            for window_records in windows:
                device_id, topic, observed_src = _describe_batch(window_records)

                if _is_internal_topic(topic):
                    print(
                        f"[IDS] skip internal system topic src={src_key} observed={observed_src} "
                        f"topic={topic}"
                    )
                    continue

                if _is_internal_or_loopback_ip(src_key) and not allow_loopback_sources:
                    print(
                        f"[IDS] skip internal/loopback source src={src_key} observed={observed_src} "
                        f"topic={topic}"
                    )
                    continue

                if not _is_sensor_topic(topic):
                    print(
                        f"[IDS] skip non-sensor topic src={src_key} observed={observed_src} "
                        f"topic={topic}"
                    )
                    continue

                results = detector.evaluate_batch({src_key: window_records})

                for result in results:
                    risk_flags_str = "|".join(result.risk_flags) if result.risk_flags else "none"

                    if not result.rule_passed:
                        violation = result.rule_violation
                        print(
                            f"[IDS] RULE_VIOLATION device={device_id} src={result.src_ip} "
                            f"observed={observed_src} topic={topic} "
                            f"type={violation.violation_type} severity={violation.severity} "
                            f"msg={violation.message}"
                        )
                        if violation.severity == "critical":
                            if _is_internal_or_loopback_ip(result.src_ip):
                                print(f"[IDS] skip blocking internal/loopback ip {result.src_ip}")
                            else:
                                try:
                                    blocker.block_ip(result.src_ip)
                                    print(f"[IDS] blocked (rule critical) {result.src_ip}")
                                except Exception as e:
                                    print(f"[IDS] failed to block {result.src_ip}: {e}")
                        continue

                    if result.skipped_reason:
                        print(
                            f"[IDS] device={device_id} src={result.src_ip} observed={observed_src} "
                            f"topic={topic} skip={result.skipped_reason} "
                            f"semantic_risk={result.semantic_risk} risk_flags={risk_flags_str} "
                            f"score={result.attack_probability:.6f} trustworthy={result.ml_trustworthy} "
                            f"pkt_count={int(result.features.get('pkt_count', 0.0))}"
                        )
                        if result.semantic_risk == "HIGH" and not block_on_high_risk:
                            continue

                    print(
                        f"[IDS] device={device_id} src={result.src_ip} observed={observed_src} "
                        f"topic={topic} score={result.attack_probability:.6f} attack={result.is_attack} "
                        f"semantic_risk={result.semantic_risk} trustworthy={result.ml_trustworthy} "
                        f"risk_flags={risk_flags_str} pkt_count={result.features.get('pkt_count', 0.0):.0f} "
                        f"iat_ms={result.features.get('mean_inter_arrival_ms', 0.0):.2f}"
                    )

                    if result.semantic_risk == "HIGH" and not block_on_high_risk:
                        continue

                    state = ip_window_state[result.src_ip]
                    state.append((result.attack_probability, result.is_attack))
                    if len(state) > ip_aggregation_window:
                        state.pop(0)

                    attack_windows = sum(1 for _, is_attack in state if is_attack)
                    windows_seen = len(state)
                    vote_ratio = (attack_windows / windows_seen) if windows_seen else 0.0
                    avg_score = sum(score for score, _ in state) / windows_seen if windows_seen else 0.0

                    ip_attack = False
                    if windows_seen >= min_windows_for_decision:
                        ip_attack = (
                            (attack_windows >= min_attack_windows and vote_ratio >= attack_vote_ratio_threshold)
                            or (avg_score >= ip_avg_score_threshold)
                        )

                    print(
                        f"[IDS] ip_eval src={result.src_ip} windows={windows_seen} attack_windows={attack_windows} "
                        f"vote_ratio={vote_ratio:.2f} avg_score={avg_score:.6f} ip_attack={ip_attack}"
                    )

                    if ip_attack:
                        if _is_internal_or_loopback_ip(result.src_ip):
                            print(f"[IDS] skip blocking internal/loopback ip {result.src_ip}")
                            continue
                        try:
                            blocker.block_ip(result.src_ip)
                            print(f"[IDS] blocked (ip_aggregated_ml) {result.src_ip}")
                        except Exception as e:
                            print(f"[IDS] failed to block {result.src_ip}: {e}")
        time.sleep(0.1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run the IDS gateway")
    parser.add_argument(
        "config_path",
        nargs="?",
        default="configs/ids_config.yaml",
        help="Path to the YAML config file",
    )
    args = parser.parse_args()
    run(args.config_path)