from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

import yaml


def _read_yaml(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        value = yaml.safe_load(handle)
    if not isinstance(value, dict):
        raise ValueError(f"IDS config must contain a YAML mapping: {path}")
    return value


def prepare_config(
    config_path: str | Path,
    defaults_path: str | Path,
    *,
    data_dir: str = "/var/lib/iot-gateway-agent",
) -> dict[str, Any]:
    target = Path(config_path)
    defaults = _read_yaml(Path(defaults_path))
    current = _read_yaml(target) if target.is_file() else {}
    merged = {**defaults, **current}
    gateway = {**defaults.get("gateway", {}), **current.get("gateway", {})}
    model = {**defaults.get("model", {}), **current.get("model", {})}

    merged["gateway"] = gateway
    merged["model"] = model
    gateway["capture_type"] = "sensor_log"
    gateway["sensor_log"] = {
        **gateway.get("sensor_log", {}),
        "path": f"{data_dir}/logs/ids_events.jsonl",
    }
    gateway["alert_log_path"] = f"{data_dir}/logs/ids_alerts.log"
    model["path"] = "models/ids_model.joblib"
    model["scaler_path"] = "models/feature_scaler.joblib"

    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("w", encoding="utf-8", newline="\n") as handle:
        yaml.safe_dump(merged, handle, sort_keys=False, allow_unicode=True)
    return merged


def main() -> None:
    parser = argparse.ArgumentParser(description="Prepare gateway IDS configuration")
    parser.add_argument("--config", required=True)
    parser.add_argument("--defaults", required=True)
    parser.add_argument("--data-dir", default="/var/lib/iot-gateway-agent")
    args = parser.parse_args()
    prepare_config(args.config, args.defaults, data_dir=args.data_dir)


if __name__ == "__main__":
    main()
