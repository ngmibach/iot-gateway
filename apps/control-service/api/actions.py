"""Gateway action routes — rotate server vs CA (split)."""

from __future__ import annotations

import ipaddress
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, status

from certs.rotate import rotate_ca, rotate_server_cert
from registry.registry import Registry

from .cert_cache import CertBundleCache
from .deps import AppState, get_cert_cache, get_registry, get_state, open_ssh_for, require_token
from .schemas import (
    DeviceBundleToken,
    RotateCARequest,
    RotateCAResponse,
    RotateServerRequest,
    RotateServerResponse,
)

router = APIRouter(dependencies=[Depends(require_token)])


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


def _resolve_gateway_ip(gw: dict[str, Any], override: Optional[str]) -> str:
    """Prefer explicit body IP; else use registry host when it is a single IP."""
    if override and str(override).strip():
        value = str(override).strip()
    else:
        value = str(gw.get("host") or "").strip()
    try:
        ipaddress.ip_address(value)
    except ValueError as exc:
        raise ValueError(
            "gateway_ip required (single IP for SAN); registry host is not an IP"
        ) from exc
    return value


def _ca_pass(body_pass: Optional[str], state: AppState) -> str:
    ca_pass = body_pass or state.settings.ca_passphrase
    if not ca_pass:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="ca_passphrase required (body or IOTGW_CA_PASSPHRASE)",
        )
    return ca_pass


@router.post(
    "/gateways/{gid}/actions/rotate-server-cert",
    response_model=RotateServerResponse,
)
def post_rotate_server_cert(
    gid: str,
    body: RotateServerRequest,
    state: AppState = Depends(get_state),
    registry: Registry = Depends(get_registry),
) -> RotateServerResponse:
    """Re-issue server cert with IP SAN; keep existing CA."""
    gw = _require_gateway(registry, gid)
    ca_pass = _ca_pass(body.ca_passphrase, state)
    try:
        gateway_ip = _resolve_gateway_ip(gw, body.gateway_ip)
    except ValueError as exc:
        raise _http_400(exc) from exc

    try:
        with open_ssh_for(state, gw) as ssh:
            result = rotate_server_cert(
                ssh,
                gateway_ip=gateway_ip,
                ca_passphrase=ca_pass,
                install_root=gw["install_root"],
                days=body.days,
            )
    except ValueError as exc:
        raise _http_400(exc) from exc
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"SSH/rotate-server failed: {exc}",
        ) from exc

    if not result.ok:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=result.message or "rotate_server_cert failed",
        )

    expires = (
        result.not_valid_after.isoformat() if result.not_valid_after is not None else None
    )
    registry.audit(
        "rotate_server_cert",
        gateway_id=gid,
        detail={
            "gateway_ip": gateway_ip,
            "status": result.status,
            "fingerprint": result.fingerprint_sha256,
            "not_valid_after": expires,
        },
    )
    return RotateServerResponse(
        ok=True,
        status=result.status,
        message=result.message,
        gateway_ip=gateway_ip,
        not_valid_after=expires,
        fingerprint_sha256=result.fingerprint_sha256,
        details=result.details,
    )


@router.post(
    "/gateways/{gid}/actions/rotate-ca",
    response_model=RotateCAResponse,
)
def post_rotate_ca(
    gid: str,
    body: RotateCARequest,
    state: AppState = Depends(get_state),
    registry: Registry = Depends(get_registry),
    cert_cache: CertBundleCache = Depends(get_cert_cache),
) -> RotateCAResponse:
    """Break-glass: new CA + server + reissue device client certs."""
    gw = _require_gateway(registry, gid)
    if not body.confirm_break_glass:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="confirm_break_glass=true required for CA rotation",
        )
    ca_pass = _ca_pass(body.ca_passphrase, state)
    try:
        gateway_ip = _resolve_gateway_ip(gw, body.gateway_ip)
    except ValueError as exc:
        raise _http_400(exc) from exc

    try:
        with open_ssh_for(state, gw) as ssh:
            result = rotate_ca(
                ssh,
                gateway_ip=gateway_ip,
                ca_passphrase=ca_pass,
                confirm_break_glass=True,
                device_ids=body.device_ids,
                registry=registry,
                gateway_id=gid,
                install_root=gw["install_root"],
            )
    except ValueError as exc:
        raise _http_400(exc) from exc
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"SSH/rotate-ca failed: {exc}",
        ) from exc

    # reload_failed → ok=False: still mint one-time tokens but redistribute=False.
    if not result.ok and result.status not in ("reload_failed",):
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=result.message or "rotate_ca failed",
        )

    tokens: list[DeviceBundleToken] = []
    for item in result.devices:
        tok = cert_cache.put(gid, item.device_id, item.cert_bundle)
        expires = (
            item.not_valid_after.isoformat()
            if item.not_valid_after is not None
            else None
        )
        tokens.append(
            DeviceBundleToken(
                device_id=item.device_id,
                cert_bundle_token=tok,
                fingerprint_sha256=item.fingerprint_sha256,
                not_valid_after=expires,
            )
        )

    redistribute = bool(result.ok)
    return RotateCAResponse(
        ok=result.ok,
        status=result.status,
        message=result.message,
        gateway_ip=gateway_ip,
        redistribute=redistribute,
        devices=tokens,
        details=result.details,
    )
