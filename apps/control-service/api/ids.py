"""Secure IDS configuration, runtime status, and Loki alert routes."""

from __future__ import annotations

import hashlib
import json
import math
import shlex
import tempfile
import uuid
from pathlib import Path
from typing import Any

import yaml
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from provisioner.agent_install import DEFAULT_AGENT_DATA, DEFAULT_AGENT_ROOT, sudo_run
from registry.registry import Registry

from .deps import (
    AppState,
    get_registry,
    get_state,
    open_ssh_for,
    require_gateway,
    require_token,
    sanitize_user_error,
)
from .query import _backend_urls, _ns_window, _proxy_get

router = APIRouter(dependencies=[Depends(require_token)])
_IDS_CONFIG_PATH = f"{DEFAULT_AGENT_DATA}/ids_config.yaml"
_IDS_SERVICE = "iot-gateway-ids.service"
_IDS_UNIT_PATH = f"/etc/systemd/system/{_IDS_SERVICE}"
_ALERT_QUERY = '{job="ids-alerts"} | json | event_type="ids_alert"'


class IDSConfigUpdate(BaseModel):
    enabled: bool
    rules_enabled: bool
    ml_enabled: bool
    threshold: float = Field(ge=0.0, le=1.0, allow_inf_nan=False)
    max_message_rate_per_sec: float = Field(gt=0.0, le=1000.0, allow_inf_nan=False)
    max_clock_skew_seconds: float = Field(ge=0.0, le=3600.0, allow_inf_nan=False)
    max_connect_publish_ratio: float = Field(gt=0.0, le=1000.0, allow_inf_nan=False)
    alert_cooldown_seconds: int = Field(ge=0, le=86400)
    sudo_password: str = Field(min_length=1, max_length=256)


def _read_config(ssh: Any) -> dict[str, Any]:
    try:
        text = ssh.read_text(_IDS_CONFIG_PATH)
    except (OSError, FileNotFoundError) as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="IDS is not installed on this gateway. Provision or update the gateway first.",
        ) from exc
    try:
        config = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"gateway IDS configuration is invalid: {exc}",
        ) from exc
    if not isinstance(config, dict) or not isinstance(config.get("gateway"), dict):
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="gateway IDS configuration has an unexpected shape",
        )
    return config


def _config_values(config: dict[str, Any]) -> dict[str, Any]:
    gateway = config["gateway"]
    rules = gateway.get("behavioral_rules") or {}
    return {
        "enabled": bool(config.get("enabled", True)),
        "rules_enabled": bool(rules.get("enabled", True)),
        "ml_enabled": bool(gateway.get("ml_enabled", True)),
        "threshold": float(
            0.05
            if gateway.get("suspicious_threshold") is None
            else gateway["suspicious_threshold"]
        ),
        "max_message_rate_per_sec": float(
            rules.get("max_message_rate_per_sec", 1.5)
        ),
        "max_clock_skew_seconds": float(rules.get("max_clock_skew_seconds", 2.5)),
        "max_connect_publish_ratio": float(
            rules.get("max_connect_publish_ratio", 1.15)
        ),
        "alert_cooldown_seconds": int(rules.get("alert_cooldown_seconds", 60)),
    }


def _remote_status(ssh: Any, *, install_root: str) -> dict[str, Any]:
    model_path = f"{install_root.rstrip('/')}/ids/models/ids_model.joblib"
    runtime_python = f"{install_root.rstrip('/')}/ids-venv/bin/python"
    result = ssh.run(
        "systemctl show -p LoadState -p ActiveState -p SubState -p Result "
        f"{_IDS_SERVICE} 2>/dev/null || true; "
        f"test -f {shlex.quote(_IDS_UNIT_PATH)} && echo unit_present=1; "
        f"test -f {shlex.quote(_IDS_CONFIG_PATH)} && echo config_present=1; "
        f"test -f {shlex.quote(model_path)} && echo model_present=1; "
        f"test -x {shlex.quote(runtime_python)} && echo runtime_present=1; true",
        timeout=20.0,
    )
    if not result.ok:
        raise RuntimeError((result.stderr or result.stdout or "gateway status check failed").strip())
    values: dict[str, str] = {}
    for line in result.stdout.splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            values[key.strip()] = value.strip()
    installed = (
        values.get("unit_present") == "1"
        and values.get("config_present") == "1"
    )
    active = values.get("ActiveState", "unknown")
    if not installed:
        service_state = "not_installed"
        config_values = None
    else:
        config_values = _config_values(_read_config(ssh))
        if active == "active":
            service_state = "running"
        elif active == "failed" or values.get("Result") not in (None, "success"):
            service_state = "failed"
        else:
            service_state = "stopped"
    model_ready = (
        values.get("model_present") == "1"
        and values.get("runtime_present") == "1"
    )
    return {
        "installed": installed,
        "configured_enabled": (
            bool(config_values["enabled"]) if config_values is not None else None
        ),
        "service_state": service_state,
        "active_state": active,
        "sub_state": values.get("SubState", "unknown"),
        "result": values.get("Result", "unknown"),
        "model_ready": model_ready,
        "runtime_ready": service_state == "running" and model_ready,
        "config": config_values,
    }


@router.get("/gateways/{gateway_id}/ids/config")
def get_ids_config(
    gateway_id: str,
    state: AppState = Depends(get_state),
    registry: Registry = Depends(get_registry),
) -> dict[str, Any]:
    gateway = require_gateway(registry, gateway_id)
    try:
        with open_ssh_for(state, gateway) as ssh:
            return _config_values(_read_config(ssh))
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        detail = sanitize_user_error(str(exc), fallback="SSH/IDS config read failed")
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"SSH/IDS config read failed: {detail}",
        ) from exc


@router.get("/gateways/{gateway_id}/ids/status")
def get_ids_status(
    gateway_id: str,
    state: AppState = Depends(get_state),
    registry: Registry = Depends(get_registry),
) -> dict[str, Any]:
    gateway = require_gateway(registry, gateway_id)
    try:
        with open_ssh_for(state, gateway) as ssh:
            return _remote_status(
                ssh,
                install_root=str(gateway.get("install_root") or DEFAULT_AGENT_ROOT),
            )
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        detail = sanitize_user_error(str(exc), fallback="SSH/IDS status check failed")
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"SSH/IDS status check failed: {detail}",
        ) from exc


@router.post("/gateways/{gateway_id}/ids/config")
def update_ids_config(
    gateway_id: str,
    body: IDSConfigUpdate,
    state: AppState = Depends(get_state),
    registry: Registry = Depends(get_registry),
) -> dict[str, Any]:
    gateway = require_gateway(registry, gateway_id)
    numeric = (
        body.threshold,
        body.max_message_rate_per_sec,
        body.max_clock_skew_seconds,
        body.max_connect_publish_ratio,
    )
    if not all(math.isfinite(value) for value in numeric):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="IDS numeric settings must be finite values",
        )

    try:
        with open_ssh_for(state, gateway) as ssh:
            config = _read_config(ssh)
            rules = config["gateway"].setdefault("behavioral_rules", {})
            config["enabled"] = body.enabled
            rules["enabled"] = body.rules_enabled
            config["gateway"]["ml_enabled"] = body.ml_enabled
            config["gateway"]["suspicious_threshold"] = body.threshold
            rules["max_message_rate_per_sec"] = body.max_message_rate_per_sec
            rules["max_clock_skew_seconds"] = body.max_clock_skew_seconds
            rules["max_connect_publish_ratio"] = body.max_connect_publish_ratio
            rules["alert_cooldown_seconds"] = body.alert_cooldown_seconds

            with tempfile.NamedTemporaryFile(
                "w", suffix=".yaml", encoding="utf-8", delete=False
            ) as tmp:
                yaml.safe_dump(config, tmp, sort_keys=False)
                local_path = Path(tmp.name)
            remote_tmp = f"/tmp/iotgw-ids-config-{uuid.uuid4().hex}.yaml"
            remote_config_tmp = f"{_IDS_CONFIG_PATH}.{uuid.uuid4().hex}.tmp"
            try:
                ssh.upload_file(local_path, remote_tmp, mode=0o600)
                service_action = (
                    f"systemctl enable {_IDS_SERVICE} && "
                    f"systemctl restart {_IDS_SERVICE} && "
                    f"systemctl is-active --quiet {_IDS_SERVICE}"
                    if body.enabled
                    else f"systemctl disable --now {_IDS_SERVICE} && "
                    f"if systemctl is-active --quiet {_IDS_SERVICE}; then exit 1; fi"
                )
                command = (
                    "set -eu; "
                    f"trap 'rm -f {shlex.quote(remote_tmp)} "
                    f"{shlex.quote(remote_config_tmp)}' EXIT; "
                    f"install -d -o root -g root {shlex.quote(DEFAULT_AGENT_DATA)}; "
                    f"install -o root -g root -m 0644 {shlex.quote(remote_tmp)} "
                    f"{shlex.quote(remote_config_tmp)}; "
                    f"mv -f {shlex.quote(remote_config_tmp)} "
                    f"{shlex.quote(_IDS_CONFIG_PATH)}; "
                    f"{service_action}"
                )
                result = sudo_run(
                    ssh,
                    command,
                    sudo_password=body.sudo_password,
                    timeout=90.0,
                )
                if not result.ok:
                    detail = (result.stderr or result.stdout or "IDS service operation failed").strip()
                    raise RuntimeError(detail[:800])
            finally:
                local_path.unlink(missing_ok=True)
            status_result = _remote_status(
                ssh,
                install_root=str(gateway.get("install_root") or DEFAULT_AGENT_ROOT),
            )
            if body.enabled and not status_result["runtime_ready"]:
                raise HTTPException(
                    status_code=status.HTTP_502_BAD_GATEWAY,
                    detail="IDS config was saved but the IDS service/model is not running. "
                    "Inspect the gateway IDS service journal and retry.",
                )
            if not body.enabled and status_result["service_state"] == "running":
                raise HTTPException(
                    status_code=status.HTTP_502_BAD_GATEWAY,
                    detail="IDS disable was requested but the IDS service is still running.",
                )
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        detail = sanitize_user_error(str(exc), fallback="gateway IDS operation failed")
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"SSH/IDS config update failed: {detail}",
        ) from exc

    registry.audit(
        "ids_config_updated",
        gateway_id=gateway_id,
        detail=_config_values(config),
    )
    return {"ok": True, "config": _config_values(config), "status": status_result}


@router.get("/ids/alerts")
def get_ids_alerts(
    range: str = Query(default="1h", pattern=r"^(15m|1h|6h|24h|7d)$"),
    severity: str | None = Query(default=None, pattern=r"^(critical|warning|info)$"),
    limit: int = Query(default=500, ge=1, le=2000),
    gateway_id: str | None = Query(default=None, max_length=64),
    state: AppState = Depends(get_state),
    registry: Registry = Depends(get_registry),
) -> dict[str, Any]:
    loki, _ = _backend_urls(state)
    start_ns, end_ns = _ns_window(range)
    query = _ALERT_QUERY
    if gateway_id:
        gateway = registry.get_gateway(gateway_id)
        if gateway is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"gateway {gateway_id!r} not found",
            )
        query = (
            '{job="ids-alerts", gateway='
            + json.dumps(str(gateway["host"]))
            + '} | json | event_type="ids_alert"'
        )

    result = _proxy_get(
        f"{loki}/loki/api/v1/query_range",
        {
            "query": query,
            "start": start_ns,
            "end": end_ns,
            "limit": limit,
            "direction": "backward",
        },
    )
    alerts: list[dict[str, Any]] = []
    for stream in result.get("data", {}).get("result", []) or []:
        for timestamp, line in stream.get("values", []) or []:
            try:
                alert = json.loads(line)
            except (TypeError, json.JSONDecodeError):
                continue
            if not isinstance(alert, dict):
                continue
            if severity and str(alert.get("severity", "")).lower() != severity:
                continue
            alert["id"] = hashlib.sha256(
                f"{timestamp}:{line}".encode("utf-8")
            ).hexdigest()[:20]
            alert.setdefault("occurred_at", alert.get("@timestamp") or timestamp)
            alerts.append(alert)
    alerts.sort(key=lambda item: str(item.get("occurred_at", "")), reverse=True)
    return {"range": range, "count": len(alerts), "alerts": alerts}
