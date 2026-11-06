"""Authenticated IDS configuration, lifecycle, and Loki alert routes."""

from __future__ import annotations

import json
import shlex
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from provisioner.agent_install import (
    DEFAULT_AGENT_ROOT,
    DEFAULT_IDS_CONFIG,
    IDS_SERVICE_NAME,
    AgentInstallError,
    sudo_run,
)
from provisioner.ssh import SSHSession
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
from .query import _http_client

router = APIRouter(dependencies=[Depends(require_token)])

_RANGES = {"15m": 900, "1h": 3600, "6h": 21600, "24h": 86400, "7d": 604800}
_IDS_ROOT = f"{DEFAULT_AGENT_ROOT}/ids"
_IDS_PYTHON = f"{DEFAULT_AGENT_ROOT}/ids-venv/bin/python"
_STATUS_PROPS = ("LoadState", "ActiveState", "SubState", "Result")


class IDSConfigUpdate(BaseModel):
    enabled: bool | None = None
    rules_enabled: bool | None = None
    ml_enabled: bool | None = None
    threshold: float | None = Field(default=None, ge=0.0, le=1.0)
    max_message_rate_per_sec: float | None = Field(default=None, gt=0.0, le=1000.0)
    max_clock_skew_seconds: float | None = Field(default=None, ge=0.0, le=3600.0)
    max_connect_publish_ratio: float | None = Field(default=None, gt=0.0, le=1000.0)
    alert_cooldown_seconds: int | None = Field(default=None, ge=0, le=86400)
    sudo_password: str | None = None


def _ssh_run(ssh: SSHSession, command: str, *, timeout: float = 30.0) -> str:
    result = ssh.run(command, timeout=timeout)
    if not result.ok:
        detail = (result.stderr or result.stdout).strip()
        raise RuntimeError(detail[:400] or "remote gateway command failed")
    return result.stdout.strip()


def _remote_config(ssh: SSHSession) -> dict[str, Any]:
    script = (
        "import json,sys,yaml; "
        f"p=open({DEFAULT_IDS_CONFIG!r}, encoding='utf-8'); "
        "value=yaml.safe_load(p); "
        "print(json.dumps(value if isinstance(value,dict) else {}))"
    )
    output = _ssh_run(
        ssh,
        f"{shlex.quote(_IDS_PYTHON)} -c {shlex.quote(script)}",
    )
    value = json.loads(output)
    if not isinstance(value, dict) or not isinstance(value.get("gateway"), dict):
        raise RuntimeError("gateway returned an invalid IDS configuration")
    return value


def _status(ssh: SSHSession, gateway_id: str) -> dict[str, Any]:
    props: dict[str, str] = {}
    service = ssh.run(
        f"systemctl show {shlex.quote(IDS_SERVICE_NAME)} --no-page "
        + " ".join(f"--property={key}" for key in _STATUS_PROPS),
        timeout=20.0,
    )
    if not service.ok:
        detail = (service.stderr or service.stdout).strip()
        raise RuntimeError(detail[:400] or "could not read IDS systemd status")
    for line in service.stdout.splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            props[key] = value.strip()

    checks = _ssh_run(
        ssh,
        "printf 'config=%s\\nmodel=%s\\nruntime=%s\\n' "
        f"\"$(test -f {shlex.quote(DEFAULT_IDS_CONFIG)} && echo 1 || echo 0)\" "
        f"\"$(test -f {shlex.quote(_IDS_ROOT + '/models/ids_model.joblib')} && "
        "echo 1 || echo 0)\" "
        f"\"$(test -x {shlex.quote(_IDS_PYTHON)} && echo 1 || echo 0)\"",
    )
    checks_by_name = dict(
        line.split("=", 1) for line in checks.splitlines() if "=" in line
    )
    config_exists = checks_by_name.get("config") == "1"
    unit_exists = props.get("LoadState") == "loaded"
    installed = config_exists and unit_exists
    runtime_ready = checks_by_name.get("runtime") == "1"
    model_ready = checks_by_name.get("model") == "1"

    active = props.get("ActiveState", "")
    if not installed:
        service_state = "not_installed"
    elif active == "active":
        service_state = "running"
    elif active == "failed":
        service_state = "failed"
    else:
        service_state = "stopped"

    config: dict[str, Any] | None = None
    if installed and runtime_ready:
        full = _remote_config(ssh)
        config = full["gateway"]
    configured_enabled = bool((config or {}).get("enabled", False))
    return {
        "gateway_id": gateway_id,
        "installed": installed,
        "configured_enabled": configured_enabled,
        "service_state": service_state,
        "active_state": active or "not-installed",
        "sub_state": props.get("SubState", ""),
        "result": props.get("Result", ""),
        "model_ready": model_ready,
        "runtime_ready": runtime_ready,
        "config": config,
    }


def _with_gateway_ssh(
    state: AppState, registry: Registry, gateway_id: str
) -> tuple[dict[str, Any], Any]:
    gateway = require_gateway(registry, gateway_id)
    return gateway, open_ssh_for(state, gateway)


@router.get("/gateways/{gid}/ids/status")
def get_ids_status(
    gid: str,
    state: AppState = Depends(get_state),
    registry: Registry = Depends(get_registry),
) -> dict[str, Any]:
    gateway, ssh_context = _with_gateway_ssh(state, registry, gid)
    try:
        with ssh_context as ssh:
            return _status(ssh, gid)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=sanitize_user_error(f"IDS status failed: {exc}"),
        ) from exc


@router.get("/gateways/{gid}/ids/config")
def get_ids_config(
    gid: str,
    state: AppState = Depends(get_state),
    registry: Registry = Depends(get_registry),
) -> dict[str, Any]:
    gateway, ssh_context = _with_gateway_ssh(state, registry, gid)
    try:
        with ssh_context as ssh:
            current = _status(ssh, gid)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=sanitize_user_error(f"IDS config read failed: {exc}"),
        ) from exc
    if not current["installed"]:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="provision or update the gateway first",
        )
    return {"gateway_id": gid, "config": current["config"]}


@router.post("/gateways/{gid}/ids/config")
def post_ids_config(
    gid: str,
    body: IDSConfigUpdate,
    state: AppState = Depends(get_state),
    registry: Registry = Depends(get_registry),
) -> dict[str, Any]:
    gateway, ssh_context = _with_gateway_ssh(state, registry, gid)
    password = (body.sudo_password or "").strip()
    if not password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="sudo_password required",
        )
    try:
        with ssh_context as ssh:
            current_status = _status(ssh, gid)
            if not current_status["installed"] or not current_status["runtime_ready"]:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="provision or update the gateway first",
                )
            config = _remote_config(ssh)
            gateway_config = config["gateway"]
            rule_config = gateway_config.setdefault("behavioral_rules", {})
            updates = body.model_dump(exclude_none=True, exclude={"sudo_password"})
            if "enabled" in updates:
                gateway_config["enabled"] = updates["enabled"]
            if "rules_enabled" in updates:
                rule_config["enabled"] = updates["rules_enabled"]
            if "ml_enabled" in updates:
                gateway_config["ml_enabled"] = updates["ml_enabled"]
            if "threshold" in updates:
                gateway_config["suspicious_threshold"] = updates["threshold"]
            for key in (
                "max_message_rate_per_sec",
                "max_clock_skew_seconds",
                "max_connect_publish_ratio",
                "alert_cooldown_seconds",
            ):
                if key in updates:
                    rule_config[key] = updates[key]

            render_script = (
                "import json,sys,yaml; "
                "yaml.safe_dump(json.load(sys.stdin),sys.stdout,"
                "sort_keys=False,allow_unicode=True)"
            )
            rendered = ssh.run(
                f"{shlex.quote(_IDS_PYTHON)} -c {shlex.quote(render_script)}",
                timeout=30.0,
                stdin=json.dumps(config, ensure_ascii=False),
            )
            if not rendered.ok:
                raise RuntimeError(
                    (rendered.stderr or rendered.stdout).strip()[:400]
                    or "could not serialize IDS configuration"
                )
            local_path: Path | None = None
            remote_tmp = f"/tmp/iotgw-ids-config-{uuid.uuid4().hex}.yaml"
            remote_atomic = f"{DEFAULT_IDS_CONFIG}.new-{uuid.uuid4().hex}"
            try:
                with tempfile.NamedTemporaryFile(
                    "w",
                    encoding="utf-8",
                    newline="\n",
                    suffix=".yaml",
                    delete=False,
                ) as handle:
                    handle.write(rendered.stdout)
                    local_path = Path(handle.name)
                ssh.upload_file(local_path, remote_tmp, mode=0o600)
                installed = sudo_run(
                    ssh,
                    f"install -o root -g root -m 0644 {shlex.quote(remote_tmp)} "
                    f"{shlex.quote(remote_atomic)} && "
                    f"mv -f {shlex.quote(remote_atomic)} "
                    f"{shlex.quote(DEFAULT_IDS_CONFIG)} && "
                    f"rm -f {shlex.quote(remote_tmp)}",
                    sudo_password=password,
                    timeout=30.0,
                )
                if not installed.ok:
                    raise RuntimeError(
                        (installed.stderr or installed.stdout).strip()[:400]
                        or "could not atomically install IDS configuration"
                    )
            finally:
                if local_path is not None:
                    local_path.unlink(missing_ok=True)
                ssh.run(f"rm -f {shlex.quote(remote_tmp)}", timeout=15.0)

            if gateway_config.get("enabled"):
                action = f"systemctl enable --now {IDS_SERVICE_NAME}"
            else:
                action = f"systemctl disable --now {IDS_SERVICE_NAME}"
            changed = sudo_run(
                ssh,
                action,
                sudo_password=password,
                timeout=120.0,
            )
            if not changed.ok:
                raise RuntimeError(
                    (changed.stderr or changed.stdout).strip()[:400]
                    or "could not change IDS service state"
                )
            result = _status(ssh, gid)
    except HTTPException:
        raise
    except AgentInstallError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=sanitize_user_error(str(exc)),
        ) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=sanitize_user_error(f"IDS config update failed: {exc}"),
        ) from exc

    enabled = bool(gateway_config.get("enabled"))
    if (enabled and result["service_state"] != "running") or (
        not enabled and result["service_state"] == "running"
    ):
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=(
                "IDS service state did not match the requested configuration "
                f"(service_state={result['service_state']}, result={result['result']})"
            ),
        )
    registry.audit(
        "ids_config_update",
        gateway_id=gid,
        detail={
            "enabled": enabled,
            "rules_enabled": rule_config.get("enabled"),
            "ml_enabled": gateway_config.get("ml_enabled", True),
        },
    )
    return result


@router.get("/ids/alerts")
def get_ids_alerts(
    range: Literal["15m", "1h", "6h", "24h", "7d"] = Query(default="1h"),
    severity: str | None = Query(default=None),
    gateway_id: str | None = Query(default=None),
    limit: int = Query(default=500, ge=1, le=2000),
    state: AppState = Depends(get_state),
    registry: Registry = Depends(get_registry),
) -> dict[str, Any]:
    gateway = require_gateway(registry, gateway_id) if gateway_id else None
    host = str(gateway.get("host") or "") if gateway else ""
    selector = '{job="ids-alerts"'
    if host:
        selector += f", gateway={json.dumps(host)}"
    query = selector + '} | json | event_type="ids_alert"'
    if severity:
        query += f" | severity={json.dumps(severity)}"
    end = int(time.time())
    params = {
        "query": query,
        "start": (end - _RANGES[range]) * 1_000_000_000,
        "end": end * 1_000_000_000,
        "limit": limit,
        "direction": "backward",
    }
    try:
        response = _http_client().get(
            f"{state.settings.loki_url.rstrip('/')}/loki/api/v1/query_range",
            params=params,
        )
        if response.status_code != 200:
            raise RuntimeError(
                f"Loki returned {response.status_code}: {response.text[:300]}"
            )
        payload = response.json()
        if not isinstance(payload, dict) or not isinstance(
            payload.get("data"), dict
        ):
            raise RuntimeError("Loki returned an invalid IDS alert response")
        streams = payload["data"].get("result")
        if not isinstance(streams, list):
            raise RuntimeError("Loki returned an invalid IDS alert result")
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=sanitize_user_error(f"Loki IDS alerts query failed: {exc}"),
        ) from exc

    alerts: list[dict[str, Any]] = []
    for stream in streams:
        if not isinstance(stream, dict) or not isinstance(stream.get("values"), list):
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail="Loki returned an invalid IDS alert stream",
            )
        for value in stream["values"]:
            if not isinstance(value, (list, tuple)) or len(value) != 2:
                raise HTTPException(
                    status_code=status.HTTP_502_BAD_GATEWAY,
                    detail="Loki returned an invalid IDS alert record",
                )
            timestamp_ns, raw_line = value
            try:
                item = json.loads(raw_line)
            except (TypeError, json.JSONDecodeError):
                continue
            if not isinstance(item, dict) or item.get("event_type") != "ids_alert":
                continue
            item.setdefault("timestamp", timestamp_ns)
            item["id"] = f"{timestamp_ns}:{len(alerts)}"
            alerts.append(item)
    alerts.sort(key=lambda item: str(item.get("timestamp") or ""), reverse=True)
    return {"alerts": alerts[:limit], "count": min(len(alerts), limit)}
