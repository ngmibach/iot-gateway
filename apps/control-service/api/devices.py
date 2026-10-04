"""Device register / list / delete / cert-bundle routes."""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status

from actions.playbooks import register_device, unregister_device
from actions.validate import validate_ip_or_cidr, validate_topic, validate_user_id
from registry.registry import Registry

from .cert_cache import CertBundleCache
from .deps import AppState, get_cert_cache, get_registry, get_state, open_ssh_for, require_token
from .schemas import (
    DeviceOut,
    GatewayOut,
    RegisterDeviceRequest,
    RegisterDeviceResponse,
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


def _device_out(row: dict[str, Any]) -> DeviceOut:
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
    )


def _expires_unix(iso: str | None) -> int | None:
    if not iso:
        return None
    try:
        dt = datetime.fromisoformat(iso)
        return int(dt.timestamp())
    except ValueError:
        return None


def _require_gateway(registry: Registry, gid: str) -> dict[str, Any]:
    gw = registry.get_gateway(gid)
    if gw is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"gateway {gid!r} not found",
        )
    return gw


def _http_400(exc: ValueError) -> HTTPException:
    return HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))


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
    _require_gateway(registry, gid)
    flag = None if monitor_enabled is None else (1 if monitor_enabled else 0)
    return [_device_out(r) for r in registry.list_devices(gid, monitor_enabled=flag)]


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
    gw = _require_gateway(registry, gid)
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
        raise _http_400(exc) from exc

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
        raise _http_400(exc) from exc
    except Exception as exc:  # noqa: BLE001 — transport / remote failures
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"SSH/register failed: {exc}",
        ) from exc

    if not result.ok:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=result.message or "register_device failed",
        )

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
    )
    registry.audit(
        "register_device",
        gateway_id=gid,
        device_id=user_id,
        detail={
            "ip": ip,
            "status": result.status,
            "cert_fingerprint": result.cert_fingerprint,
        },
    )

    token = None
    if result.cert_bundle:
        token = cert_cache.put(gid, user_id, result.cert_bundle)

    return RegisterDeviceResponse(
        device=_device_out(device),
        cert_bundle_token=token,
        status=result.status,
        message=result.message,
        idempotent=idempotent,
    )


@router.delete("/gateways/{gid}/devices/{device_id}", status_code=status.HTTP_200_OK)
def delete_device(
    gid: str,
    device_id: str,
    remove_ip: bool = Query(default=False),
    state: AppState = Depends(get_state),
    registry: Registry = Depends(get_registry),
) -> dict[str, Any]:
    gw = _require_gateway(registry, gid)
    try:
        device_id = validate_user_id(device_id)
    except ValueError as exc:
        raise _http_400(exc) from exc

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
        raise _http_400(exc) from exc
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
    _require_gateway(registry, gid)
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
