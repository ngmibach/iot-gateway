"""Prepare the gateway-local IDS config while preserving operator settings."""

from __future__ import annotations

import argparse
import json
import os
import tempfile
from pathlib import Path
from typing import Any

import yaml

_DEFAULT_CONFIG = Path(__file__).resolve().parents[1] / "configs" / "ids_config.yaml"


def prepare_config(
    config_path: str | Path,
    *,
    event_log: str,
    alert_log: str,
    mosquitto_log: str,
) -> dict[str, Any]:
    path = Path(config_path)
    if path.exists():
        with path.open("r", encoding="utf-8") as fh:
            config = yaml.safe_load(fh)
    else:
        with _DEFAULT_CONFIG.open("r", encoding="utf-8") as fh:
            config = yaml.safe_load(fh)
    if not isinstance(config, dict) or not isinstance(config.get("gateway"), dict):
        raise ValueError(f"invalid IDS config shape at {path}")

    gateway = config["gateway"]
    gateway.setdefault("sensor_log", {})["path"] = event_log
    gateway["alert_log_path"] = alert_log
    gateway.setdefault("mosquitto_log", {})["path"] = mosquitto_log
    gateway.setdefault("haproxy_log", {})["path"] = ""
    rules = gateway.setdefault("behavioral_rules", {})
    rules["enforce_allowed_ips"] = False
    rules["expected_source_ips"] = {}
    config.setdefault("enabled", True)
    model = config.setdefault("model", {})
    if not isinstance(model, dict):
        raise ValueError(f"invalid IDS model config at {path}")
    metadata_path = _DEFAULT_CONFIG.parent.parent / "models" / "model_metadata.json"
    with metadata_path.open("r", encoding="utf-8") as fh:
        metadata = json.load(fh)
    features = metadata.get("feature_columns")
    if not isinstance(features, list) or not features:
        raise ValueError(f"bundled IDS model metadata is invalid at {metadata_path}")
    model["path"] = "models/ids_model.joblib"
    model["scaler_path"] = "models/feature_scaler.joblib"
    model["expected_features"] = features

    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            yaml.safe_dump(config, fh, sort_keys=False)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(temp_name, 0o644)
        os.replace(temp_name, path)
    finally:
        Path(temp_name).unlink(missing_ok=True)
    return config


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    parser.add_argument("--event-log", required=True)
    parser.add_argument("--alert-log", required=True)
    parser.add_argument("--mosquitto-log", required=True)
    args = parser.parse_args()
    config = prepare_config(
        args.config,
        event_log=args.event_log,
        alert_log=args.alert_log,
        mosquitto_log=args.mosquitto_log,
    )
    print("enabled=true" if config.get("enabled", True) else "enabled=false")


if __name__ == "__main__":
    main()
