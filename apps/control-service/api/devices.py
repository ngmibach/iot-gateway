"""Device register / list / delete / cert-bundle routes."""

from __future__ import annotations

import json
import time
from datetime import datetime
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status

from actions.discover_sensors import discover_sensor_hosts
from actions.fake_sensors import (
    DEFAULT_BEHAVIORS,
    FakeAllocation,
    create_netns,
    enable_and_start_unit,
    ensure_fake_runtime,
    feed_fake_certs,
    install_fake_files,
    restart_fake_unit,
    stop_fake_unit,
    teardown_fake,
    update_fake_config,
)
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
from .device_meta import is_fake_meta, merge_device_meta, parse_meta
from .schemas import (
    CreateFakeDeviceRequest,
    DeviceOut,
    DiscoverSensorsResponse,
    FakeActionRequest,
    FakeActionResponse,
    FakeBehaviors,
    FakeDeviceOut,
    FeedFakeCertRequest,
    GatewayOut,
    KafkaCapacityOut,
    PatchFakeDeviceRequest,
    PatchFakeDeviceResponse,
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
    return parse_meta(row.get("meta_json"))


def _behaviors_out(raw: Any) -> FakeBehaviors | None:
    if not isinstance(raw, dict):
        return None
    merged = dict(DEFAULT_BEHAVIORS)
    for key in DEFAULT_BEHAVIORS:
        if key in raw:
            merged[key] = bool(raw[key])
    return FakeBehaviors(**merged)


def _fake_out(meta: dict[str, Any]) -> FakeDeviceOut | None:
    if not is_fake_meta(meta):
        return None
    block = meta.get("fake")
    if not isinstance(block, dict):
        return FakeDeviceOut()
    interval = block.get("send_interval_ms")
    fed_at = block.get("cert_fed_at")
    return FakeDeviceOut(
        ip=str(block["ip"]) if block.get("ip") is not None else None,
        status=str(block["status"]) if block.get("status") is not None else None,
        send_interval_ms=int(interval) if interval is not None else None,
        topic=str(block["topic"]) if block.get("topic") is not None else None,
        netns=str(block["netns"]) if block.get("netns") is not None else None,
        unit=str(block["unit"]) if block.get("unit") is not None else None,
        bridge=str(block["bridge"]) if block.get("bridge") is not None else None,
        behaviors=_behaviors_out(block.get("behaviors")),
        cert_fed_at=int(fed_at) if fed_at is not None else None,
        cert_feed_fingerprint=(
            str(block["cert_feed_fingerprint"])
            if block.get("cert_feed_fingerprint") is not None
            else None
        ),
        last_error=(
            str(block["last_error"]) if block.get("last_error") is not None else None
        ),
    )


def _require_fake_device(
    registry: Registry, gid: str, device_id: str
) -> dict[str, Any]:
    row = registry.get_device(gid, device_id)
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"device {device_id!r} not found on gateway {gid!r}",
        )
    if not is_fake_meta(_meta_dict(row)):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"device {device_id!r} is not a fake sensor",
        )
    return row


def _default_publish_topic(user_id: str, topic_rw: str | None) -> str:
    if topic_rw:
        base = topic_rw.rstrip("#").rstrip("/").rstrip("+").rstrip("/")
        if base:
            return f"{base}/process" if not base.endswith("/process") else base
    return f"sensors/{user_id}/process"


def _pem_text(value: bytes | str | None) -> str | None:
    if value is None:
        return None
    if isinstance(value, bytes):
        return value.decode("utf-8")
    return value


def _mark_fake_error(
    registry: Registry,
    gid: str,
    device_id: str,
    *,
    message: str,
) -> dict[str, Any]:
    row = registry.get_device(gid, device_id)
    prev = _meta_dict(row) if row else {}
    meta = merge_device_meta(
        prev,
        is_fake=True,
        fake={"status": "error", "last_error": message[:400]},
    )
    return registry.upsert_device(gid, device_id, meta_json=meta)


def _feed_and_record(
    ssh: Any,
    *,
    registry: Registry,
    gid: str,
    device_id: str,
    ca_pem: bytes | str,
    client_crt_pem: bytes | str,
    client_key_pem: bytes | str,
    fingerprint: str | None,
    sudo_password: str | None = None,
    install_root: str,
) -> tuple[Any, dict[str, Any]]:
    """Write certs into fake runtime, restart unit, update ``cert_fed_*`` meta."""
    fed = feed_fake_certs(
        ssh,
        device_id,
        ca_pem=ca_pem,
        client_crt_pem=client_crt_pem,
        client_key_pem=client_key_pem,
        restart=True,
        sudo_password=sudo_password,
        install_root=install_root,
    )
    row = registry.get_device(gid, device_id)
    prev = _meta_dict(row) if row else {}
    fake_update: dict[str, Any] = {
        "cert_fed_at": int(time.time()),
        "cert_feed_fingerprint": fingerprint,
    }
    if fed.ok:
        fake_update["status"] = "running"
        fake_update["last_error"] = None
    else:
        fake_update["status"] = "error"
        fake_update["last_error"] = (fed.message or "feed_fake_certs failed")[:400]
    meta = merge_device_meta(prev, is_fake=True, fake=fake_update)
    device = registry.upsert_device(gid, device_id, meta_json=meta)
    return fed, device


def _device_out(row: dict[str, Any]) -> DeviceOut:
    meta = _meta_dict(row)
    kafka_topic = meta.get("kafka_topic")
    retention = meta.get("kafka_retention_bytes")
    fake = is_fake_meta(meta)
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
        is_fake=fake,
        fake=_fake_out(meta) if fake else None,
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
    is_fake: Optional[bool] = Query(default=None),
    registry: Registry = Depends(get_registry),
) -> list[DeviceOut]:
    """List devices; optional ``is_fake`` filters fake vs real sensors."""
    require_gateway(registry, gid)
    flag = None if monitor_enabled is None else (1 if monitor_enabled else 0)
    out = [_device_out(r) for r in registry.list_devices(gid, monitor_enabled=flag)]
    if is_fake is not None:
        out = [d for d in out if d.is_fake is bool(is_fake)]
    return out


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
    "/gateways/{gid}/devices/fake",
    response_model=RegisterDeviceResponse,
    status_code=status.HTTP_200_OK,
)
def post_create_fake_device(
    gid: str,
    body: CreateFakeDeviceRequest,
    state: AppState = Depends(get_state),
    registry: Registry = Depends(get_registry),
    cert_cache: CertBundleCache = Depends(get_cert_cache),
) -> RegisterDeviceResponse:
    """Allocate netns IP, register like a real sensor, feed certs, start unit."""
    gw = require_gateway(registry, gid)
    existing = registry.get_device(gid, body.user_id)
    idempotent = existing is not None
    if existing is not None and not is_fake_meta(_meta_dict(existing)):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                f"device {body.user_id!r} already exists as a real sensor; "
                "choose another id"
            ),
        )

    ca_pass = body.ca_passphrase or state.settings.ca_passphrase
    if not ca_pass:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="ca_passphrase required (body or IOTGW_CA_PASSPHRASE)",
        )
    sudo_password = body.sudo_password

    try:
        user_id = validate_user_id(body.user_id)
        topic_rw = body.topic_rw_arg() or f"sensors/{user_id}/#"
        topic_r = body.topic_r_arg()
        topic_rw = validate_topic(topic_rw)
        if topic_r is not None:
            topic_r = validate_topic(topic_r)
        publish_topic = (
            validate_topic(body.topic.strip())
            if body.topic and body.topic.strip()
            else _default_publish_topic(user_id, topic_rw)
        )
    except ValueError as exc:
        raise http_400(exc) from exc

    install_root = gw["install_root"]
    alloc: FakeAllocation | None = None
    registered = False

    try:
        with open_ssh_for(state, gw) as ssh:
            runtime = ensure_fake_runtime(
                ssh, sudo_password=sudo_password, install_root=install_root
            )
            if not runtime.ok:
                raise HTTPException(
                    status_code=status.HTTP_502_BAD_GATEWAY,
                    detail=runtime.message or "failed to prepare fake runtime",
                )
            netns = create_netns(
                ssh, user_id, sudo_password=sudo_password, install_root=install_root
            )
            if not netns.ok:
                raise HTTPException(
                    status_code=status.HTTP_502_BAD_GATEWAY,
                    detail=netns.message or "failed to create fake netns",
                )
            alloc_raw = (netns.details or {}).get("allocation") or {}
            alloc = FakeAllocation(
                device_id=user_id,
                ip=str(alloc_raw["ip"]),
                host_num=int(alloc_raw["host_num"]),
                host_if=str(alloc_raw["host_if"]),
                ns_if=str(alloc_raw["ns_if"]),
                netns=str(alloc_raw["netns"]),
                unit=str(alloc_raw["unit"]),
                bridge=str(alloc_raw.get("bridge") or "iotgw-fake"),
            )

            result = register_device(
                ssh,
                user_id=user_id,
                password=body.password,
                ip=alloc.ip,
                topic_rw=topic_rw,
                topic_r=topic_r,
                install_root=install_root,
                ca_passphrase=ca_pass,
            )
            if not result.ok:
                teardown_fake(
                    ssh, user_id, sudo_password=sudo_password, install_root=install_root
                )
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
            registered = True

            installed = install_fake_files(
                ssh,
                user_id,
                config={
                    "device_id": user_id,
                    "mqtt_user": user_id,
                    "mqtt_password": body.password,
                    "broker_host": "10.255.0.1",
                    "broker_port": 8883,
                    "topic": publish_topic,
                    "send_interval_ms": int(body.send_interval_ms),
                    "behaviors": dict(DEFAULT_BEHAVIORS),
                },
                payload=body.payload,
                ca_pem=_pem_text(result.ca_crt_pem),
                client_crt_pem=_pem_text(result.client_crt_pem),
                client_key_pem=_pem_text(result.client_key_pem),
                install_root=install_root,
            )
            if not installed.ok:
                teardown_fake(
                    ssh, user_id, sudo_password=sudo_password, install_root=install_root
                )
                raise HTTPException(
                    status_code=status.HTTP_502_BAD_GATEWAY,
                    detail=installed.message or "failed to install fake files",
                )

            started = enable_and_start_unit(
                ssh, user_id, sudo_password=sudo_password, install_root=install_root
            )
            unit_ok = started.ok
            unit_msg = started.message or ""
    except HTTPException:
        raise
    except ValueError as exc:
        raise http_400(exc) from exc
    except Exception as exc:  # noqa: BLE001
        if alloc is not None and not registered:
            try:
                with open_ssh_for(state, gw) as ssh:
                    teardown_fake(
                        ssh,
                        user_id,
                        sudo_password=sudo_password,
                        install_root=install_root,
                    )
            except Exception:
                pass
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"SSH/fake create failed: {exc}",
        ) from exc

    assert alloc is not None
    kafka_topic = (result.details or {}).get("kafka_topic") or kafka_topic_name(user_id)
    kafka_retention = (result.details or {}).get("kafka_retention_bytes")
    kafka_capacity_raw = (result.details or {}).get("kafka_capacity")
    fed_at = int(time.time()) if result.client_crt_pem else None
    fake_meta = {
        "ip": alloc.ip,
        "netns": alloc.netns,
        "unit": alloc.unit,
        "bridge": alloc.bridge,
        "status": "running" if unit_ok else "error",
        "send_interval_ms": int(body.send_interval_ms),
        "topic": publish_topic,
        "behaviors": dict(DEFAULT_BEHAVIORS),
        "cert_fed_at": fed_at,
        "cert_feed_fingerprint": result.cert_fingerprint,
        "last_error": None if unit_ok else (unit_msg or "unit start failed")[:400],
    }
    prev_meta = _meta_dict(existing) if existing else {}
    meta = merge_device_meta(
        prev_meta,
        kafka_topic=kafka_topic,
        kafka_retention_bytes=kafka_retention,
        is_fake=True,
        fake=fake_meta,
    )
    topics_rw = body.topics_rw() or [topic_rw]
    topics_r = body.topics_r() or None
    device = registry.upsert_device(
        gid,
        user_id,
        ip=alloc.ip,
        topics_rw=topics_rw,
        topics_r=topics_r,
        monitor_enabled=1 if body.monitor_enabled else 0,
        cert_expires_at=_expires_unix(result.cert_expires_at),
        cert_fingerprint=result.cert_fingerprint,
        meta_json=meta,
    )
    registry.audit(
        "create_fake_device",
        gateway_id=gid,
        device_id=user_id,
        detail={
            "ip": alloc.ip,
            "status": "running" if unit_ok else "error",
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

    status_str = result.status if unit_ok else "degraded"
    message = result.message or "Fake sensor created."
    if not unit_ok:
        message = f"{message} Unit start failed: {unit_msg}".strip()

    return RegisterDeviceResponse(
        device=_device_out(device),
        cert_bundle_token=token,
        status=status_str,
        message=message,
        idempotent=idempotent,
        kafka_topic=kafka_topic,
        kafka_capacity=capacity_out,
    )


@router.get(
    "/gateways/{gid}/devices/{device_id}/fake",
    response_model=FakeDeviceOut,
)
def get_fake_device(
    gid: str,
    device_id: str,
    registry: Registry = Depends(get_registry),
) -> FakeDeviceOut:
    """Return fake runtime summary from registry meta."""
    require_gateway(registry, gid)
    try:
        device_id = validate_user_id(device_id)
    except ValueError as exc:
        raise http_400(exc) from exc
    row = _require_fake_device(registry, gid, device_id)
    out = _fake_out(_meta_dict(row))
    return out or FakeDeviceOut()


@router.patch(
    "/gateways/{gid}/devices/{device_id}/fake",
    response_model=PatchFakeDeviceResponse,
)
def patch_fake_device(
    gid: str,
    device_id: str,
    body: PatchFakeDeviceRequest,
    state: AppState = Depends(get_state),
    registry: Registry = Depends(get_registry),
) -> PatchFakeDeviceResponse:
    """Update simulate config on the gateway and refresh registry meta."""
    gw = require_gateway(registry, gid)
    try:
        device_id = validate_user_id(device_id)
    except ValueError as exc:
        raise http_400(exc) from exc
    row = _require_fake_device(registry, gid, device_id)

    updates: dict[str, Any] = {}
    if body.send_interval_ms is not None:
        updates["send_interval_ms"] = int(body.send_interval_ms)
    if body.topic is not None:
        try:
            updates["topic"] = validate_topic(body.topic.strip())
        except ValueError as exc:
            raise http_400(exc) from exc
    if body.behaviors is not None:
        updates["behaviors"] = body.behaviors.model_dump()
    if not updates and body.payload is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="no fake config changes provided",
        )

    install_root = gw["install_root"]
    try:
        with open_ssh_for(state, gw) as ssh:
            if updates:
                updated = update_fake_config(
                    ssh,
                    device_id,
                    updates=updates,
                    restart=False,
                    sudo_password=body.sudo_password,
                    install_root=install_root,
                )
                if not updated.ok and updated.status == "failed":
                    raise HTTPException(
                        status_code=status.HTTP_502_BAD_GATEWAY,
                        detail=updated.message or "failed to update fake config",
                    )
            if body.payload is not None:
                from actions.fake_sensors import _paths as _fake_paths
                from actions.shellutil import shell_quote

                paths = _fake_paths(install_root)
                if isinstance(body.payload, (bytes, bytearray)):
                    payload_obj: Any = json.loads(body.payload.decode("utf-8"))
                elif isinstance(body.payload, str):
                    payload_obj = (
                        json.loads(body.payload) if body.payload.strip() else {"hello": 1}
                    )
                else:
                    payload_obj = body.payload
                ssh.run(f"mkdir -p {shell_quote(paths.fake_device_dir(device_id))}")
                ssh.write_text(
                    paths.fake_payload_path(device_id),
                    json.dumps(payload_obj, indent=2, ensure_ascii=False) + "\n",
                    mode=0o644,
                )
            restarted = restart_fake_unit(
                ssh,
                device_id,
                sudo_password=body.sudo_password,
                install_root=install_root,
            )
            if not restarted.ok:
                _mark_fake_error(registry, gid, device_id, message=restarted.message)
                raise HTTPException(
                    status_code=status.HTTP_502_BAD_GATEWAY,
                    detail=restarted.message or "restart failed after fake update",
                )
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"SSH/fake update failed: {exc}",
        ) from exc

    prev = _meta_dict(row)
    fake_update: dict[str, Any] = {"last_error": None, "status": "running"}
    if "send_interval_ms" in updates:
        fake_update["send_interval_ms"] = updates["send_interval_ms"]
    if "topic" in updates:
        fake_update["topic"] = updates["topic"]
    if "behaviors" in updates:
        fake_update["behaviors"] = updates["behaviors"]
    meta = merge_device_meta(prev, is_fake=True, fake=fake_update)
    device = registry.upsert_device(gid, device_id, meta_json=meta)
    registry.audit(
        "update_fake_device",
        gateway_id=gid,
        device_id=device_id,
        detail={"keys": sorted(updates.keys()) + (["payload"] if body.payload is not None else [])},
    )
    return PatchFakeDeviceResponse(
        device=_device_out(device),
        status="ok",
        message="Fake sensor updated.",
    )


@router.post(
    "/gateways/{gid}/devices/{device_id}/fake/start",
    response_model=FakeActionResponse,
)
def post_start_fake_device(
    gid: str,
    device_id: str,
    body: FakeActionRequest = FakeActionRequest(),
    state: AppState = Depends(get_state),
    registry: Registry = Depends(get_registry),
) -> FakeActionResponse:
    gw = require_gateway(registry, gid)
    try:
        device_id = validate_user_id(device_id)
    except ValueError as exc:
        raise http_400(exc) from exc
    _require_fake_device(registry, gid, device_id)
    sudo_password = body.sudo_password
    try:
        with open_ssh_for(state, gw) as ssh:
            started = enable_and_start_unit(
                ssh,
                device_id,
                sudo_password=sudo_password,
                install_root=gw["install_root"],
            )
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"SSH/fake start failed: {exc}",
        ) from exc
    if not started.ok:
        device = _mark_fake_error(registry, gid, device_id, message=started.message)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=started.message or "failed to start fake unit",
        )
    prev = _meta_dict(registry.get_device(gid, device_id) or {})
    meta = merge_device_meta(
        prev, is_fake=True, fake={"status": "running", "last_error": None}
    )
    device = registry.upsert_device(gid, device_id, meta_json=meta)
    registry.audit("start_fake_device", gateway_id=gid, device_id=device_id, detail={})
    return FakeActionResponse(
        device=_device_out(device), status="ok", message="Fake sensor started."
    )


@router.post(
    "/gateways/{gid}/devices/{device_id}/fake/stop",
    response_model=FakeActionResponse,
)
def post_stop_fake_device(
    gid: str,
    device_id: str,
    body: FakeActionRequest = FakeActionRequest(),
    state: AppState = Depends(get_state),
    registry: Registry = Depends(get_registry),
) -> FakeActionResponse:
    gw = require_gateway(registry, gid)
    try:
        device_id = validate_user_id(device_id)
    except ValueError as exc:
        raise http_400(exc) from exc
    _require_fake_device(registry, gid, device_id)
    sudo_password = body.sudo_password
    try:
        with open_ssh_for(state, gw) as ssh:
            stopped = stop_fake_unit(ssh, device_id, sudo_password=sudo_password)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"SSH/fake stop failed: {exc}",
        ) from exc
    if not stopped.ok:
        device = _mark_fake_error(registry, gid, device_id, message=stopped.message)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=stopped.message or "failed to stop fake unit",
        )
    prev = _meta_dict(registry.get_device(gid, device_id) or {})
    meta = merge_device_meta(
        prev, is_fake=True, fake={"status": "stopped", "last_error": None}
    )
    device = registry.upsert_device(gid, device_id, meta_json=meta)
    registry.audit("stop_fake_device", gateway_id=gid, device_id=device_id, detail={})
    return FakeActionResponse(
        device=_device_out(device), status="ok", message="Fake sensor stopped."
    )


@router.post(
    "/gateways/{gid}/devices/{device_id}/fake/feed-cert",
    response_model=ReissueCertResponse,
)
def post_feed_fake_cert(
    gid: str,
    device_id: str,
    body: FeedFakeCertRequest,
    state: AppState = Depends(get_state),
    registry: Registry = Depends(get_registry),
    cert_cache: CertBundleCache = Depends(get_cert_cache),
) -> ReissueCertResponse:
    """Reissue (default) and feed mTLS material into the fake runtime."""
    gw = require_gateway(registry, gid)
    try:
        device_id = validate_user_id(device_id)
    except ValueError as exc:
        raise http_400(exc) from exc
    _require_fake_device(registry, gid, device_id)

    ca_pem = body.ca_pem
    crt_pem = body.client_crt_pem
    key_pem = body.client_key_pem
    fingerprint: str | None = None
    expires_at: str | None = None
    cert_bundle: bytes | None = None
    result_status = "ok"
    result_message = "Certificate fed into fake runtime."

    if body.reissue or not (ca_pem and crt_pem and key_pem):
        if not body.reissue and not (ca_pem and crt_pem and key_pem):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="provide PEM material or set reissue=true",
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
                if not result.ok:
                    raise HTTPException(
                        status_code=status.HTTP_502_BAD_GATEWAY,
                        detail=result.message or "reissue failed",
                    )
                ca_pem = _pem_text(result.ca_crt_pem)
                crt_pem = _pem_text(result.client_crt_pem)
                key_pem = _pem_text(result.client_key_pem)
                fingerprint = result.cert_fingerprint
                expires_at = result.cert_expires_at
                cert_bundle = result.cert_bundle
                result_status = result.status
                result_message = result.message or result_message
                registry.upsert_device(
                    gid,
                    device_id,
                    cert_expires_at=_expires_unix(expires_at),
                    cert_fingerprint=fingerprint,
                )
                fed, device = _feed_and_record(
                    ssh,
                    registry=registry,
                    gid=gid,
                    device_id=device_id,
                    ca_pem=ca_pem or "",
                    client_crt_pem=crt_pem or "",
                    client_key_pem=key_pem or "",
                    fingerprint=fingerprint,
                    sudo_password=body.sudo_password,
                    install_root=gw["install_root"],
                )
        except HTTPException:
            raise
        except ValueError as exc:
            raise http_400(exc) from exc
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"SSH/feed-cert failed: {exc}",
            ) from exc
        if not fed.ok:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=fed.message or "feed_fake_certs failed",
            )
    else:
        try:
            with open_ssh_for(state, gw) as ssh:
                row = registry.get_device(gid, device_id)
                fingerprint = (row or {}).get("cert_fingerprint")
                fed, device = _feed_and_record(
                    ssh,
                    registry=registry,
                    gid=gid,
                    device_id=device_id,
                    ca_pem=ca_pem or "",
                    client_crt_pem=crt_pem or "",
                    client_key_pem=key_pem or "",
                    fingerprint=fingerprint,
                    sudo_password=body.sudo_password,
                    install_root=gw["install_root"],
                )
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"SSH/feed-cert failed: {exc}",
            ) from exc
        if not fed.ok:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=fed.message or "feed_fake_certs failed",
            )

    registry.audit(
        "feed_fake_cert",
        gateway_id=gid,
        device_id=device_id,
        detail={"cert_fingerprint": fingerprint, "reissue": bool(body.reissue)},
    )
    token = None
    if cert_bundle:
        token = cert_cache.put(gid, device_id, cert_bundle)
    return ReissueCertResponse(
        device=_device_out(device),
        cert_bundle_token=token,
        status=result_status,
        message=result_message,
    )


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
    # Real-sensor register path: refresh kafka meta and clear any fake marker.
    prev_meta = _meta_dict(existing) if existing else {}
    meta = merge_device_meta(
        prev_meta,
        kafka_topic=kafka_topic,
        kafka_retention_bytes=kafka_retention,
        clear_fake=True,
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

    is_fake = is_fake_meta(_meta_dict(row))
    try:
        with open_ssh_for(state, gw) as ssh:
            result = reissue_device_cert(
                ssh,
                user_id=device_id,
                ca_passphrase=ca_pass,
                install_root=gw["install_root"],
                cert_days=int(body.days),
            )
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
            # Fake sensors: also install material into fake/<id>/certs and restart.
            if is_fake and result.ca_crt_pem and result.client_crt_pem and result.client_key_pem:
                fed, device = _feed_and_record(
                    ssh,
                    registry=registry,
                    gid=gid,
                    device_id=device_id,
                    ca_pem=result.ca_crt_pem,
                    client_crt_pem=result.client_crt_pem,
                    client_key_pem=result.client_key_pem,
                    fingerprint=result.cert_fingerprint,
                    install_root=gw["install_root"],
                )
                if not fed.ok:
                    raise HTTPException(
                        status_code=status.HTTP_502_BAD_GATEWAY,
                        detail=fed.message or "reissue ok but feed_fake_certs failed",
                    )
    except HTTPException:
        raise
    except ValueError as exc:
        raise http_400(exc) from exc
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"SSH/reissue failed: {exc}",
        ) from exc

    registry.audit(
        "reissue_device_cert",
        gateway_id=gid,
        device_id=device_id,
        detail={
            "status": result.status,
            "cert_fingerprint": result.cert_fingerprint,
            "fed_fake": is_fake,
        },
    )
    token = None
    if result.cert_bundle:
        token = cert_cache.put(gid, device_id, result.cert_bundle)
    message = result.message or "Certificate reissued."
    if is_fake:
        message = "Certificate reissued and fed into fake runtime."
    return ReissueCertResponse(
        device=_device_out(device),
        cert_bundle_token=token,
        status=result.status,
        message=message,
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
    is_fake = is_fake_meta(_meta_dict(row))
    try:
        with open_ssh_for(state, gw) as ssh:
            if is_fake:
                torn = teardown_fake(
                    ssh, device_id, install_root=gw["install_root"]
                )
                if not torn.ok and torn.status == "failed":
                    raise HTTPException(
                        status_code=status.HTTP_502_BAD_GATEWAY,
                        detail=torn.message or "fake teardown failed",
                    )
            result = unregister_device(
                ssh,
                user_id=device_id,
                ip=ip if remove_ip else None,
                remove_ip=remove_ip and bool(ip),
                install_root=gw["install_root"],
            )
    except HTTPException:
        raise
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
        detail={"remove_ip": remove_ip, "status": result.status, "was_fake": is_fake},
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
