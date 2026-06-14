from __future__ import annotations

import argparse
import json
import re
from collections import defaultdict
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Evaluate IDS multi-sensor logs at IP level"
    )
    parser.add_argument("--log", required=True, help="Path to IDS log file")
    parser.add_argument(
        "--attack-devices",
        required=True,
        help="Comma-separated device ids expected to attack (e.g. sensor1,sensor3)",
    )
    parser.add_argument(
        "--output-json",
        default="gateway/ids/logs/multi_sensor_ip_eval.json",
        help="Output JSON path",
    )
    return parser.parse_args()


def _bool_from_text(value: str) -> bool:
    return str(value).strip().lower() == "true"


def main() -> None:
    args = parse_args()
    log_path = Path(args.log)
    if not log_path.exists():
        raise FileNotFoundError(f"Log file not found: {log_path}")

    attack_devices = {x.strip() for x in args.attack_devices.split(",") if x.strip()}
    if not attack_devices:
        raise ValueError("attack-devices is empty")

    decision_re = re.compile(
        r"\[IDS\] device=(?P<device>\S+) src=(?P<src>\S+) observed=(?P<observed>\S+) "
        r"topic=(?P<topic>\S+) score=(?P<score>[0-9.eE+-]+) attack=(?P<attack>True|False)"
    )
    ip_eval_re = re.compile(
        r"\[IDS\] ip_eval src=(?P<src>\S+) windows=(?P<windows>\d+) attack_windows=(?P<attack_windows>\d+) "
        r"vote_ratio=(?P<vote_ratio>[0-9.]+) avg_score=(?P<avg_score>[0-9.eE+-]+) ip_attack=(?P<ip_attack>True|False)"
    )
    blocked_re = re.compile(r"\[IDS\] blocked \(ip_aggregated_ml\) (?P<src>\S+)")

    device_to_ips: dict[str, set[str]] = defaultdict(set)
    ip_to_devices: dict[str, set[str]] = defaultdict(set)
    ip_window_pred: dict[str, list[bool]] = defaultdict(list)
    ip_eval_last: dict[str, dict] = {}
    ip_eval_history: dict[str, list[bool]] = defaultdict(list)
    blocked_ips: set[str] = set()

    for line in log_path.read_text(encoding="utf-8", errors="ignore").splitlines():
        m = decision_re.search(line)
        if m:
            d = m.groupdict()
            src = d["src"]
            device = d["device"]
            pred_attack = _bool_from_text(d["attack"])

            device_to_ips[device].add(src)
            ip_to_devices[src].add(device)
            ip_window_pred[src].append(pred_attack)
            continue

        m = ip_eval_re.search(line)
        if m:
            d = m.groupdict()
            src = d["src"]
            ip_eval_last[src] = {
                "windows": int(d["windows"]),
                "attack_windows": int(d["attack_windows"]),
                "vote_ratio": float(d["vote_ratio"]),
                "avg_score": float(d["avg_score"]),
                "ip_attack": _bool_from_text(d["ip_attack"]),
            }
            ip_eval_history[src].append(_bool_from_text(d["ip_attack"]))
            continue

        m = blocked_re.search(line)
        if m:
            blocked_ips.add(m.group("src"))

    ips = sorted(set(ip_to_devices.keys()) | set(ip_eval_last.keys()) | set(blocked_ips))

    rows = []
    tp = tn = fp = fn = 0
    for ip in ips:
        devices = sorted(ip_to_devices.get(ip, set()))
        is_attack_gt = any(d in attack_devices for d in devices)
        ip_eval = ip_eval_last.get(ip, {})
        ip_attack_pred = bool(any(ip_eval_history.get(ip, [])) or (ip in blocked_ips))

        if is_attack_gt and ip_attack_pred:
            tp += 1
        elif (not is_attack_gt) and (not ip_attack_pred):
            tn += 1
        elif (not is_attack_gt) and ip_attack_pred:
            fp += 1
        elif is_attack_gt and (not ip_attack_pred):
            fn += 1

        rows.append(
            {
                "ip": ip,
                "devices": devices,
                "gt_attack": is_attack_gt,
                "pred_ip_attack": ip_attack_pred,
                "blocked": ip in blocked_ips,
                "window_pred_attack_rate": (
                    float(sum(ip_window_pred.get(ip, [])) / len(ip_window_pred[ip]))
                    if ip_window_pred.get(ip)
                    else 0.0
                ),
                "window_count": int(len(ip_window_pred.get(ip, []))),
                "ip_eval_attack_any": bool(any(ip_eval_history.get(ip, []))),
                "ip_eval": ip_eval,
            }
        )

    precision = float(tp / (tp + fp)) if (tp + fp) else 0.0
    recall = float(tp / (tp + fn)) if (tp + fn) else 0.0
    fpr = float(fp / (fp + tn)) if (fp + tn) else 0.0
    fnr = float(fn / (fn + tp)) if (fn + tp) else 0.0

    output = {
        "attack_devices": sorted(attack_devices),
        "ips": rows,
        "metrics": {
            "ip_count": int(len(rows)),
            "tp": int(tp),
            "tn": int(tn),
            "fp": int(fp),
            "fn": int(fn),
            "precision": precision,
            "recall": recall,
            "fpr": fpr,
            "fnr": fnr,
        },
        "device_to_ips": {k: sorted(v) for k, v in sorted(device_to_ips.items())},
    }

    output_path = Path(args.output_json)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(output, indent=2), encoding="utf-8")

    print(json.dumps(output["metrics"], indent=2))
    print(f"Saved IP-level report: {output_path}")


if __name__ == "__main__":
    main()
