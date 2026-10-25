"""Device register / list / delete / cert-bundle routes."""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status

from actions.discover_sensors import discover_sensor_hosts
from actions.kafka_capacity import kafka_topic_name
from actions.playbooks import (
    gateway_kafka_capacity,
    register_device,
    reissue_device_cert,
    unregister_device,
)
from actions.validate import validate_ip_or_cidr, validate_topic, validate_user_id
from registry.registry import Registry

from .cert_cache import CertBundleCache
from .deps import (
    AppState,
    get_cert_cache,
    get_registry,
    get_state,
    http_400,
    open_ssh_for,
    require_gateway,
    require_token,
)
from .schemas import (
    DeviceOut,
    DiscoverSensorsResponse,
    GatewayOut,
    KafkaCapacityOut,
    RegisterDeviceRequest,
    RegisterDeviceResponse,
    ReissueCertRequest,
    ReissueCertResponse,
    UpdateDeviceRequest,
    UpdateDeviceResponse,
)

# Authenticated control routes.
router = APIRouter(dependencies=[Depends(require_token)])
# Cert-bundle uses one-time ?token= only (browser link cannot send API headers).
public_router = APIRouter()


def _parse_json_field(value: Any) -> Any:
    if value is None:
        return None
    if isinstance(value, (list, dict)):
        return value
    if isinstance(value, str):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return value
    return value


def _meta_dict(row: dict[str, Any]) -> dict[str, Any]:
    meta = _parse_json_field(row.get("meta_json"))
    return meta if isinstance(meta, dict) else {}


def _device_out(row: dict[str, Any]) -> DeviceOut:
    meta = _meta_dict(row)
    kafka_topic = meta.get("kafka_topic")
    retention = meta.get("kafka_retention_bytes")
    return DeviceOut(
        id=row["id"],
        gateway_id=row["gateway_id"],
        ip=row.get("ip"),
        topics_rw=_parse_json_field(row.get("topics_rw")),
        topics_r=_parse_json_field(row.get("topics_r")),
        monitor_enabled=bool(row.get("monitor_enabled", 1)),
        cert_expires_at=row.get("cert_expires_at"),
        cert_fingerprint=row.get("cert_fingerprint"),
        created_at=row.get("created_at"),
        kafka_topic=str(kafka_topic) if kafka_topic else None,
        kafka_retention_bytes=int(retention) if retention is not None else None,
    )


def _capacity_out(plan: Any) -> KafkaCapacityOut:
    return KafkaCapacityOut(
        total_storage_bytes=int(plan.total_storage_bytes),
        topic_retention_bytes=int(plan.topic_retention_bytes),
        safety_ratio=float(plan.safety_ratio),
        budget_bytes=int(plan.budget_bytes),
        max_sensors=int(plan.max_sensors),
        registered_sensors=int(plan.registered_sensors),
        remaining_slots=int(plan.remaining_slots),
        at_capacity=bool(plan.at_capacity),
    )


def _expires_unix(iso: str | None) -> int | None:
    if not iso:
        return None
    try:
        dt = datetime.fromisoformat(iso)
        return int(dt.timestamp())
    except ValueError:
        return None


@router.get("/gateways", response_model=list[GatewayOut])
def list_gateways(registry: Registry = Depends(get_registry)) -> list[GatewayOut]:
    out: list[GatewayOut] = []
    for gw in registry.list_gateways():
        out.append(
            GatewayOut(
                id=gw["id"],
                host=gw["host"],
                ssh_user=gw["ssh_user"],
                install_root=gw["install_root"],
                fingerprint=gw["fingerprint"],
                monitoring_ip=gw.get("monitoring_ip"),
                status=gw.get("status"),
                node_instance="gateway",
            )
        )
    return out


@router.get("/gateways/{gid}/devices", response_model=list[DeviceOut])
def list_devices(
    gid: str,
    monitor_enabled: Optional[bool] = Query(default=None),
    registry: Registry = Depends(get_registry),
) -> list[DeviceOut]:
    require_gateway(registry, gid)
    flag = None if monitor_enabled is None else (1 if monitor_enabled else 0)
    return [_device_out(r) for r in registry.list_devices(gid, monitor_enabled=flag)]


@router.post(
    "/gateways/{gid}/devices/discover",
    response_model=DiscoverSensorsResponse,
)
def post_discover_sensors(
    gid: str,
    state: AppState = Depends(get_state),
    registry: Registry = Depends(get_registry),
) -> DiscoverSensorsResponse:
    """List LAN neighbor IPs on the gateway (excludes the gateway itself)."""
    gw = require_gateway(registry, gid)
    try:
        with open_ssh_for(state, gw) as ssh:
            out = discover_sensor_hosts(ssh)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"sensor discover failed: {exc}",
        ) from exc
    return DiscoverSensorsResponse(
        hosts=list(out.get("hosts") or []),
        gateway_ips=list(out.get("gateway_ips") or []),
    )


@router.get(
    "/gateways/{gid}/kafka/capacity",
    response_model=KafkaCapacityOut,
)
def get_kafka_capacity(
    gid: str,
    state: AppState = Depends(get_state),
    registry: Registry = Depends(get_registry),
) -> KafkaCapacityOut:
    """Return how many sensors this gateway may still register (disk × 70%)."""
    gw = require_gateway(registry, gid)
    try:
        with open_ssh_for(state, gw) as ssh:
            plan = gateway_kafka_capacity(ssh, install_root=gw["install_root"])
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"kafka capacity probe failed: {exc}",
        ) from exc
    return _capacity_out(plan)


@router.post(
    "/gateways/{gid}/devices",
    response_model=RegisterDeviceResponse,
    status_code=status.HTTP_200_OK,
)
def post_register_device(
    gid: str,
    body: RegisterDeviceRequest,
    state: AppState = Depends(get_state),
    registry: Registry = Depends(get_registry),
    cert_cache: CertBundleCache = Depends(get_cert_cache),
) -> RegisterDeviceResponse:
    gw = require_gateway(registry, gid)
    existing = registry.get_device(gid, body.user_id)
    idempotent = existing is not None

    ca_pass = body.ca_passphrase or state.settings.ca_passphrase
    if not ca_pass:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="ca_passphrase required (body or IOTGW_CA_PASSPHRASE)",
        )

    # Validate before opening SSH so bad input is 400, not 502.
    try:
        user_id = validate_user_id(body.user_id)
        ip = validate_ip_or_cidr(body.ip)
        topic_rw = body.topic_rw_arg()
        topic_r = body.topic_r_arg()
        if topic_rw is not None:
            topic_rw = validate_topic(topic_rw)
        if topic_r is not None:
            topic_r = validate_topic(topic_r)
    except ValueError as exc:
        raise http_400(exc) from exc

    try:
        with open_ssh_for(state, gw) as ssh:
            result = register_device(
                ssh,
                user_id=user_id,
                password=body.password,
                ip=ip,
                topic_rw=topic_rw,
                topic_r=topic_r,
                install_root=gw["install_root"],
                ca_passphrase=ca_pass,
            )
    except ValueError as exc:
        raise http_400(exc) from exc
    except Exception as exc:  # noqa: BLE001 — transport / remote failures
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"SSH/register failed: {exc}",
        ) from exc

    if not result.ok:
        capacity = (result.details or {}).get("kafka_capacity")
        if capacity and "capacity full" in (result.message or "").lower():
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "message": result.message or "gateway Kafka capacity full",
                    "kafka_capacity": capacity,
                },
            )
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=result.message or "register_device failed",
        )

    kafka_topic = (result.details or {}).get("kafka_topic") or kafka_topic_name(user_id)
    kafka_retention = (result.details or {}).get("kafka_retention_bytes")
    kafka_capacity_raw = (result.details or {}).get("kafka_capacity")
    meta = {
        "kafka_topic": kafka_topic,
        "kafka_retention_bytes": kafka_retention,
    }

    topics_rw = body.topics_rw() or None
    topics_r = body.topics_r() or None
    device = registry.upsert_device(
        gid,
        user_id,
        ip=ip,
        topics_rw=topics_rw,
        topics_r=topics_r,
        monitor_enabled=1 if body.monitor_enabled else 0,
        cert_expires_at=_expires_unix(result.cert_expires_at),
        cert_fingerprint=result.cert_fingerprint,
        meta_json=meta,
    )
    registry.audit(
        "register_device",
        gateway_id=gid,
        device_id=user_id,
        detail={
            "ip": ip,
            "status": result.status,
            "cert_fingerprint": result.cert_fingerprint,
            "kafka_topic": kafka_topic,
        },
    )

    token = None
    if result.cert_bundle:
        token = cert_cache.put(gid, user_id, result.cert_bundle)

    capacity_out = None
    if isinstance(kafka_capacity_raw, dict):
        capacity_out = KafkaCapacityOut(
            total_storage_bytes=int(kafka_capacity_raw.get("total_storage_bytes") or 0),
            topic_retention_bytes=int(
                kafka_capacity_raw.get("topic_retention_bytes") or 0
            ),
            safety_ratio=float(kafka_capacity_raw.get("safety_ratio") or 0.7),
            budget_bytes=int(kafka_capacity_raw.get("budget_bytes") or 0),
            max_sensors=int(kafka_capacity_raw.get("max_sensors") or 0),
            registered_sensors=int(kafka_capacity_raw.get("registered_sensors") or 0),
            remaining_slots=int(kafka_capacity_raw.get("remaining_slots") or 0),
            at_capacity=int(kafka_capacity_raw.get("remaining_slots") or 0) <= 0,
        )

    return RegisterDeviceResponse(
        device=_device_out(device),
        cert_bundle_token=token,
        status=result.status,
        message=result.message,
        idempotent=idempotent,
        kafka_topic=kafka_topic,
        kafka_capacity=capacity_out,
    )


def _topic_list_equal(a: Any, b: list[str]) -> bool:
    """Compare stored JSON topic field to a desired list."""
    if a is None:
        return not b
    if isinstance(a, str):
        try:
            a = json.loads(a)
        except json.JSONDecodeError:
            a = [a] if a.strip() else []
    if isinstance(a, list):
        left = [str(x).strip() for x in a if str(x).strip()]
    else:
        left = [str(a).strip()] if str(a).strip() else []
    return left == b


@router.patch(
    "/gateways/{gid}/devices/{device_id}",
    response_model=UpdateDeviceResponse,
    status_code=status.HTTP_200_OK,
)
def patch_device(
    gid: str,
    device_id: str,
    body: UpdateDeviceRequest,
    state: AppState = Depends(get_state),
    registry: Registry = Depends(get_registry),
    cert_cache: CertBundleCache = Depends(get_cert_cache),
) -> UpdateDeviceResponse:
    """Update a registered device.

    Monitor-only → local registry. IP / topics / password → register playbook
    (password required).
    """
    gw = require_gateway(registry, gid)
    try:
        device_id = validate_user_id(device_id)
    except ValueError as exc:
        raise http_400(exc) from exc

    row = registry.get_device(gid, device_id)
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"device {device_id!r} not found on gateway {gid!r}",
        )

    desired_ip = body.ip if body.ip is not None else (row.get("ip") or "")
    desired_topics_rw = (
        body.topics_rw()
        if body.topic_readwrite is not None
        else (_parse_json_field(row.get("topics_rw")) or [])
    )
    if not isinstance(desired_topics_rw, list):
        desired_topics_rw = [str(desired_topics_rw)] if desired_topics_rw else []
    desired_topics_r = (
        body.topics_r()
        if body.topic_read is not None
        else (_parse_json_field(row.get("topics_r")) or [])
    )
    if not isinstance(desired_topics_r, list):
        desired_topics_r = [str(desired_topics_r)] if desired_topics_r else []

    ip_changed = body.ip is not None and str(body.ip).strip() != str(row.get("ip") or "")
    topics_changed = (
        (
            body.topic_readwrite is not None
            and not _topic_list_equal(row.get("topics_rw"), body.topics_rw())
        )
        or (
            body.topic_read is not None
            and not _topic_list_equal(row.get("topics_r"), body.topics_r())
        )
    )
    password_set = bool((body.password or "").strip())
    playbook_needed = ip_changed or topics_changed or password_set

    if not playbook_needed and body.monitor_enabled is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="no changes provided",
        )

    if playbook_needed:
        if not password_set:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="password required to update IP, topics, or credentials on the gateway",
            )
        ca_pass = body.ca_passphrase or state.settings.ca_passphrase
        if not ca_pass:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="ca_passphrase required (body or IOTGW_CA_PASSPHRASE)",
            )
        try:
            ip = validate_ip_or_cidr(str(desired_ip).strip())
            topic_rw = body.topic_rw_arg() if body.topic_readwrite is not None else None
            topic_r = body.topic_r_arg() if body.topic_read is not None else None
            if topic_rw is None and desired_topics_rw:
                topic_rw = validate_topic(str(desired_topics_rw[0]))
            if topic_r is None and desired_topics_r:
                topic_r = validate_topic(str(desired_topics_r[0]))
            if topic_rw is not None:
                topic_rw = validate_topic(topic_rw)
            if topic_r is not None:
                topic_r = validate_topic(topic_r)
        except ValueError as exc:
            raise http_400(exc) from exc

        try:
            with open_ssh_for(state, gw) as ssh:
                result = register_device(
                    ssh,
                    user_id=device_id,
                    password=str(body.password),
                    ip=ip,
                    topic_rw=topic_rw,
                    topic_r=topic_r,
                    install_root=gw["install_root"],
                    ca_passphrase=ca_pass,
                )
        except ValueError as exc:
            raise http_400(exc) from exc
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"SSH/update failed: {exc}",
            ) from exc

        if not result.ok:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=result.message or "device update failed",
            )

        monitor = (
            (1 if body.monitor_enabled else 0)
            if body.monitor_enabled is not None
            else row.get("monitor_enabled", 1)
        )
        device = registry.upsert_device(
            gid,
            device_id,
            ip=ip,
            topics_rw=desired_topics_rw or None,
            topics_r=desired_topics_r or None,
            monitor_enabled=monitor,
            cert_expires_at=_expires_unix(result.cert_expires_at),
            cert_fingerprint=result.cert_fingerprint,
        )
        registry.audit(
            "update_device",
            gateway_id=gid,
            device_id=device_id,
            detail={"ip": ip, "status": result.status, "playbook": True},
        )
        token = None
        if result.cert_bundle:
            token = cert_cache.put(gid, device_id, result.cert_bundle)
        return UpdateDeviceResponse(
            device=_device_out(device),
            cert_bundle_token=token,
            status=result.status,
            message=result.message or "Device updated.",
            playbook=True,
        )

    # Monitor-only (or other registry-only) update.
    device = registry.upsert_device(
        gid,
        device_id,
        monitor_enabled=1 if body.monitor_enabled else 0,
    )
    registry.audit(
        "update_device",
        gateway_id=gid,
        device_id=device_id,
        detail={"monitor_enabled": bool(body.monitor_enabled), "playbook": False},
    )
    return UpdateDeviceResponse(
        device=_device_out(device),
        status="ok",
        message="Monitor setting saved.",
        playbook=False,
    )


@router.post(
    "/gateways/{gid}/devices/{device_id}/reissue-cert",
    response_model=ReissueCertResponse,
)
def post_reissue_cert(
    gid: str,
    device_id: str,
    body: ReissueCertRequest,
    state: AppState = Depends(get_state),
    registry: Registry = Depends(get_registry),
    cert_cache: CertBundleCache = Depends(get_cert_cache),
) -> ReissueCertResponse:
    """Re-sign a client cert for an existing device; returns a one-time download token."""
    gw = require_gateway(registry, gid)
    try:
        device_id = validate_user_id(device_id)
    except ValueError as exc:
        raise http_400(exc) from exc

    row = registry.get_device(gid, device_id)
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"device {device_id!r} not found on gateway {gid!r}",
        )

    ca_pass = body.ca_passphrase or state.settings.ca_passphrase
    if not ca_pass:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="ca_passphrase required (body or IOTGW_CA_PASSPHRASE)",
        )

    try:
        with open_ssh_for(state, gw) as ssh:
            result = reissue_device_cert(
                ssh,
                user_id=device_id,
                ca_passphrase=ca_pass,
                install_root=gw["install_root"],
                cert_days=int(body.days),
            )
    except ValueError as exc:
        raise http_400(exc) from exc
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"SSH/reissue failed: {exc}",
        ) from exc

    if not result.ok:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=result.message or "reissue failed",
        )

    device = registry.upsert_device(
        gid,
        device_id,
        cert_expires_at=_expires_unix(result.cert_expires_at),
        cert_fingerprint=result.cert_fingerprint,
    )
    registry.audit(
        "reissue_device_cert",
        gateway_id=gid,
        device_id=device_id,
        detail={"status": result.status, "cert_fingerprint": result.cert_fingerprint},
    )
    token = None
    if result.cert_bundle:
        token = cert_cache.put(gid, device_id, result.cert_bundle)
    return ReissueCertResponse(
        device=_device_out(device),
        cert_bundle_token=token,
        status=result.status,
        message=result.message or "Certificate reissued.",
    )


@router.delete("/gateways/{gid}/devices/{device_id}", status_code=status.HTTP_200_OK)
def delete_device(
    gid: str,
    device_id: str,
    remove_ip: bool = Query(default=False),
    state: AppState = Depends(get_state),
    registry: Registry = Depends(get_registry),
) -> dict[str, Any]:
    gw = require_gateway(registry, gid)
    try:
        device_id = validate_user_id(device_id)
    except ValueError as exc:
        raise http_400(exc) from exc

    row = registry.get_device(gid, device_id)
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"device {device_id!r} not found on gateway {gid!r}",
        )
    ip = row.get("ip")
    try:
        with open_ssh_for(state, gw) as ssh:
            result = unregister_device(
                ssh,
                user_id=device_id,
                ip=ip if remove_ip else None,
                remove_ip=remove_ip and bool(ip),
                install_root=gw["install_root"],
            )
    except ValueError as exc:
        raise http_400(exc) from exc
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"SSH/unregister failed: {exc}",
        ) from exc

    if not result.ok:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=result.message or "unregister_device failed",
        )

    registry.delete_device(gid, device_id)
    registry.audit(
        "unregister_device",
        gateway_id=gid,
        device_id=device_id,
        detail={"remove_ip": remove_ip, "status": result.status},
    )
    return {"ok": True, "status": result.status, "message": result.message}


@public_router.get("/gateways/{gid}/devices/{device_id}/cert-bundle")
def download_cert_bundle(
    gid: str,
    device_id: str,
    token: str = Query(..., min_length=8),
    registry: Registry = Depends(get_registry),
    cert_cache: CertBundleCache = Depends(get_cert_cache),
) -> Response:
    """One-time download; auth is the opaque token (no API token header)."""
    require_gateway(registry, gid)
    blob = cert_cache.pop(token, gateway_id=gid, device_id=device_id)
    if blob is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="cert bundle token invalid, expired, or already downloaded",
        )
    registry.audit(
        "cert_bundle_download",
        gateway_id=gid,
        device_id=device_id,
        detail={"bytes": len(blob)},
    )
    filename = f"{device_id}-cert-bundle.zip"
    return Response(
        content=blob,
        media_type="application/zip",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Cache-Control": "no-store",
        },
    )
