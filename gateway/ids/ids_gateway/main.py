from __future__ import annotations

import argparse
import json
import logging
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .alerts import build_alert_payload
from .config import load_config
from .detector import Detector
from .model import IDSModel
from .rules import DeviceLogContext, RuleEngine
from .structured_events import StructuredEventCapture

logger = logging.getLogger("ids_gateway")


class AlertWriter:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def write(self, payload: dict[str, Any]) -> None:
        payload.setdefault("event_type", "ids_alert")
        payload.setdefault("timestamp", datetime.now(timezone.utc).isoformat())
        with self.path.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(json.dumps(payload, ensure_ascii=False) + "\n")


def _process_window(
    *,
    device_id: str,
    records: list,
    detector: Detector,
    alert_writer: AlertWriter,
    history: dict[str, deque[tuple[float, bool]]],
    last_ml_alert: dict[str, float],
    threshold: float,
    aggregation_size: int,
    min_windows: int,
    min_attack_windows: int,
    vote_threshold: float,
    average_threshold: float,
    cooldown_seconds: float,
) -> None:
    if not records:
        return
    records.sort(key=lambda record: record.ts)
    topic = records[0].mqtt_topic
    result = detector.evaluate_device(
        device_id=device_id,
        src_ip="",
        records=records,
        context=DeviceLogContext(),
    )
    if not result.rule_passed and result.rule_violation is not None:
        violation = result.rule_violation
        alert_writer.write(
            build_alert_payload(
                device_id=device_id,
                source_ip="",
                topic=topic,
                alert_type="behavioral_rule",
                detection=violation.violation_type,
                severity=violation.severity,
                message=violation.message,
                score=1.0,
                score_type="rule_confidence",
            )
        )
        return
    if result.skipped_reason:
        return

    device_history = history[device_id]
    device_history.append((result.attack_probability, result.is_attack))
    if len(device_history) > aggregation_size:
        device_history.popleft()
    windows_seen = len(device_history)
    attack_windows = sum(1 for _, is_attack in device_history if is_attack)
    vote_ratio = attack_windows / windows_seen if windows_seen else 0.0
    average_score = (
        sum(score for score, _ in device_history) / windows_seen if windows_seen else 0.0
    )
    confirmed = windows_seen >= min_windows and (
        (
            attack_windows >= min_attack_windows
            and vote_ratio >= vote_threshold
        )
        or average_score >= average_threshold
    )
    now = time.time()
    if not confirmed or now - last_ml_alert.get(device_id, 0.0) < cooldown_seconds:
        return
    alert_writer.write(
        build_alert_payload(
            device_id=device_id,
            source_ip="",
            topic=topic,
            alert_type="ml_anomaly",
            detection="message_pattern_anomaly",
            severity="critical",
            message=f"ML model flagged anomalous message patterns for {device_id}",
            score=result.attack_probability,
            score_type="ml_probability",
            extra={
                "avg_score": round(average_score, 6),
                "vote_ratio": round(vote_ratio, 4),
                "threshold": threshold,
            },
        )
    )
    last_ml_alert[device_id] = now


def run(config_path: str | Path = "configs/ids_config.yaml") -> None:
    config = load_config(config_path)
    gateway_cfg = config["gateway"]
    model_cfg = config["model"]
    if not isinstance(gateway_cfg, dict) or not isinstance(model_cfg, dict):
        raise ValueError("IDS config must contain gateway and model mappings")

    if not gateway_cfg.get("enabled", False):
        raise RuntimeError("IDS is disabled in its configuration")

    model = IDSModel(
        model_path=str(model_cfg["path"]),
        scaler_path=model_cfg.get("scaler_path"),
        features=list(model_cfg["expected_features"]),
    )
    configured_threshold = gateway_cfg.get("suspicious_threshold")
    if configured_threshold is None:
        configured_threshold = model.get_default_threshold()
    if configured_threshold is None:
        raise ValueError("IDS model metadata does not define a decision threshold")
    threshold = float(configured_threshold)
    if not 0.0 <= threshold <= 1.0:
        raise ValueError("IDS threshold must be between 0 and 1")

    behavioral_cfg = dict(gateway_cfg.get("behavioral_rules") or {})
    behavioral_cfg["enabled"] = bool(behavioral_cfg.get("enabled", True))
    behavioral_cfg["enforce_allowed_ips"] = False
    behavioral_cfg["enforce_acl_users"] = False
    rule_engine = RuleEngine(behavioral_config=behavioral_cfg)
    detector = Detector(
        model=model,
        threshold=threshold,
        rule_engine=rule_engine,
        min_packets_per_window=int(gateway_cfg.get("min_model_packets", 1)),
        ml_enabled=bool(gateway_cfg.get("ml_enabled", True)),
    )
    sensor_cfg = gateway_cfg.get("sensor_log") or {}
    capture = StructuredEventCapture(sensor_cfg["path"])
    writer = AlertWriter(gateway_cfg["alert_log_path"])

    packet_window = max(float(gateway_cfg.get("packet_window_seconds", 3)), 0.1)
    interval = max(float(gateway_cfg.get("loop_interval_seconds", 1)), 0.1)
    aggregation_size = max(int(gateway_cfg.get("ip_aggregation_window", 6)), 1)
    min_windows = max(int(gateway_cfg.get("min_windows_for_decision", 4)), 1)
    min_attack_windows = max(int(gateway_cfg.get("min_attack_windows", 3)), 1)
    vote_threshold = float(gateway_cfg.get("attack_vote_ratio_threshold", 0.60))
    average_threshold = float(gateway_cfg.get("ip_avg_score_threshold", 0.68))
    cooldown = max(
        float(behavioral_cfg.get("alert_cooldown_seconds", 60)),
        0.0,
    )
    windows: dict[tuple[str, int], list] = defaultdict(list)
    history: dict[str, deque[tuple[float, bool]]] = defaultdict(
        lambda: deque(maxlen=aggregation_size)
    )
    last_ml_alert: dict[str, float] = {}
    logger.info(
        "IDS started: event_log=%s alert_log=%s threshold=%.4f",
        capture.file_path,
        writer.path,
        threshold,
    )

    while True:
        started = time.monotonic()
        for records in capture.poll_once().values():
            for record in records:
                bucket = int(record.ts // packet_window)
                windows[(record.mqtt_device_id, bucket)].append(record)

        current_bucket = int(time.time() // packet_window)
        closed = [key for key in windows if key[1] < current_bucket]
        for device_id, bucket in sorted(closed, key=lambda key: key[1]):
            records = windows.pop((device_id, bucket))
            _process_window(
                device_id=device_id,
                records=records,
                detector=detector,
                alert_writer=writer,
                history=history,
                last_ml_alert=last_ml_alert,
                threshold=threshold,
                aggregation_size=aggregation_size,
                min_windows=min_windows,
                min_attack_windows=min_attack_windows,
                vote_threshold=vote_threshold,
                average_threshold=average_threshold,
                cooldown_seconds=cooldown,
            )

        remaining = interval - (time.monotonic() - started)
        if remaining > 0:
            time.sleep(remaining)


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the gateway IDS")
    parser.add_argument(
        "--config",
        default="configs/ids_config.yaml",
        help="Path to the IDS YAML config",
    )
    args = parser.parse_args()
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    run(args.config)


if __name__ == "__main__":
    main()
