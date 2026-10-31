"""Proxy Loki/Prometheus queries + Monitoring summary helpers."""

from __future__ import annotations

import json
import threading
import time
from typing import Any, Optional

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query, status

from registry.registry import Registry

from . import queries as Q
from .deps import AppState, get_registry, get_state, require_token
from .device_meta import is_fake_meta

router = APIRouter(dependencies=[Depends(require_token)])

_TIMEOUT = 20.0
_client_lock = threading.Lock()
_shared_client: httpx.Client | None = None


def _backend_urls(state: AppState) -> tuple[str, str]:
    return state.settings.loki_url.rstrip("/"), state.settings.prometheus_url.rstrip("/")


def _http_client() -> httpx.Client:
    """Reuse one httpx client for Prom/Loki proxies.

    Opening a new Client per query costs ~0.5s on Windows, so Gateway Metric
    summaries (~25 sequential queries) were taking ~13s and the UI often showed
    browser ``Failed to fetch`` when the wizard GET proxy timed out or the
    control-service restarted mid-request.
    """
    global _shared_client
    if _shared_client is not None:
        return _shared_client
    with _client_lock:
        if _shared_client is None:
            _shared_client = httpx.Client(timeout=_TIMEOUT, trust_env=False)
        return _shared_client


def close_http_client() -> None:
    """Close the shared backend client (tests / shutdown)."""
    global _shared_client
    with _client_lock:
        client = _shared_client
        _shared_client = None
    if client is not None:
        close = getattr(client, "close", None)
        if callable(close):
            close()


def _agent_base_url(gw: Optional[dict[str, Any]]) -> Optional[str]:
    """Resolve gateway agent HTTP base (``http://host:9139``)."""
    if not gw:
        return None
    raw = str(gw.get("agent_url") or "").strip().rstrip("/")
    if raw:
        return raw
    host = str(gw.get("host") or "").strip()
    if not host:
        return None
    if "://" in host:
        return host.rstrip("/")
    return f"http://{host}:9139"


def _fetch_agent_denied(
    gw: Optional[dict[str, Any]],
    *,
    gateway_id: Optional[str],
    limit: int = 100,
    device_id: Optional[str] = None,
) -> list[dict[str, Any]]:
    """Pull recent invalid/denied message events from the gateway agent."""
    base = _agent_base_url(gw)
    if not base:
        return []
    params: dict[str, Any] = {"limit": max(1, min(int(limit or 100), 500))}
    if device_id:
        params["device_id"] = device_id
    try:
        r = _http_client().get(f"{base}/v1/denied", params=params, timeout=5.0)
    except httpx.HTTPError:
        return []
    if r.status_code != 200:
        return []
    try:
        payload = r.json()
    except ValueError:
        return []
    events = payload.get("events") if isinstance(payload, dict) else None
    if not isinstance(events, list):
        return []
    gid = (gateway_id or (gw or {}).get("id") or "").strip()
    out: list[dict[str, Any]] = []
    for raw in events:
        if not isinstance(raw, dict):
            continue
        item = {
            "arrival_ms": int(raw.get("arrival_ms") or 0),
            "reason": str(raw.get("reason") or "denied"),
            "device_id": str(raw.get("device_id") or "unknown"),
            "source_ip": str(raw.get("source_ip") or ""),
            "gateway_id": str(raw.get("gateway_id") or gid or ""),
            "detail": str(raw.get("detail") or ""),
        }
        out.append(item)
    return out


def _proxy_get(url: str, params: dict[str, Any]) -> Any:
    try:
        r = _http_client().get(url, params=params)
    except httpx.HTTPError as e:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"backend unreachable: {e}",
        ) from e
    if r.status_code != 200:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"backend {r.status_code}: {r.text[:400]}",
        )
    try:
        return r.json()
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"backend returned non-JSON: {e}",
        ) from e


def _extract_scalar(data: Any) -> float:
    if not data:
        return 0.0
    try:
        result = data.get("data", {}).get("result", [])
        if not result:
            return 0.0
        r = result[0]
        if "value" in r:
            return float(r["value"][1])
        if "values" in r and r["values"]:
            return float(r["values"][-1][1])
    except (TypeError, ValueError, IndexError, KeyError):
        pass
    return 0.0


def _ns_window(range_s: str) -> tuple[int, int]:
    """Parse a simple range like 15m / 1h / 24h into (start_ns, end_ns)."""
    end = int(time.time())
    mult = 3600
    raw = range_s.strip().lower()
    try:
        if raw.endswith("m"):
            mult = int(raw[:-1]) * 60
        elif raw.endswith("h"):
            mult = int(raw[:-1]) * 3600
        elif raw.endswith("d"):
            mult = int(raw[:-1]) * 86400
        elif raw.endswith("s"):
            mult = int(raw[:-1])
        else:
            mult = int(raw)
    except ValueError:
        mult = 3600
    start = end - max(mult, 60)
    return start * 1_000_000_000, end * 1_000_000_000


def _monitored_ids(
    registry: Registry,
    gateway_id: Optional[str],
    *,
    show_all: bool,
) -> Optional[set[str]]:
    """Return allowed device ids, or None when filter should not apply.

    - ``show_all`` → None (raw Loki view).
    - Unknown ``gateway_id`` → 404.
    - No device rows for the selected gateway(s) → None (first-run explore).
    - Devices exist → set of ``monitor_enabled=1`` ids (may be empty).
    """
    if show_all:
        return None

    if gateway_id:
        gw = registry.get_gateway(gateway_id)
        if gw is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"gateway {gateway_id!r} not found",
            )
        gateways = [gw]
    else:
        gateways = registry.list_gateways()

    any_devices = False
    ids: set[str] = set()
    for gw in gateways:
        rows = registry.list_devices(gw["id"])
        if rows:
            any_devices = True
        for row in rows:
            if int(row.get("monitor_enabled", 1) or 0) == 1:
                ids.add(str(row["id"]))
    if not any_devices:
        return None
    return ids


@router.get("/query/loki")
def query_loki(
    query: str = Query(..., min_length=1),
    start: Optional[str] = None,
    end: Optional[str] = None,
    limit: int = Query(default=1000, ge=1, le=5000),
    direction: str = Query(default="backward"),
    time: Optional[str] = None,
    state: AppState = Depends(get_state),
) -> Any:
    """Proxy to Loki instant or range query."""
    loki, _ = _backend_urls(state)
    params: dict[str, Any] = {"query": query, "limit": limit, "direction": direction}
    if start is not None and end is not None:
        params["start"] = start
        params["end"] = end
        return _proxy_get(f"{loki}/loki/api/v1/query_range", params)
    if time is not None:
        params["time"] = time
    return _proxy_get(f"{loki}/loki/api/v1/query", params)


@router.get("/query/prometheus")
def query_prometheus(
    query: str = Query(..., min_length=1),
    start: Optional[str] = None,
    end: Optional[str] = None,
    step: Optional[str] = None,
    time: Optional[str] = None,
    state: AppState = Depends(get_state),
) -> Any:
    """Proxy to Prometheus instant or range query."""
    _, prom = _backend_urls(state)
    params: dict[str, Any] = {"query": query}
    if start is not None and end is not None:
        params["start"] = start
        params["end"] = end
        params["step"] = step or "60s"
        return _proxy_get(f"{prom}/api/v1/query_range", params)
    if time is not None:
        params["time"] = time
    return _proxy_get(f"{prom}/api/v1/query", params)


def _device_meta(row: dict[str, Any]) -> dict[str, Any]:
    raw = row.get("meta_json")
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str) and raw.strip():
        try:
            parsed = json.loads(raw)
            return parsed if isinstance(parsed, dict) else {}
        except ValueError:
            return {}
    return {}


@router.get("/query/summaries/gateway")
def summary_gateway(
    time_range: str = Query(default="1h", alias="range"),
    gateway_id: Optional[str] = None,
    state: AppState = Depends(get_state),
    registry: Registry = Depends(get_registry),
) -> dict[str, Any]:
    """Gateway Activities summary (general stats + registry sensors + Kafka topics)."""
    from actions.kafka_capacity import (
        DEFAULT_TOPIC_RETENTION_BYTES,
        kafka_topic_name,
    )

    loki, prom = _backend_urls(state)
    start_ns, end_ns = _ns_window(time_range)
    start, end, step = _range_window_s(time_range)
    duration = time_range
    warnings: list[str] = []

    # Resolve gateway: explicit id, else first registry row (Activities default).
    gid = (gateway_id or "").strip() or None
    if gid:
        gw = registry.get_gateway(gid)
        if gw is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"gateway {gid!r} not found",
            )
    else:
        gateways = registry.list_gateways()
        gw = gateways[0] if gateways else None
        gid = str(gw["id"]) if gw else None

    def loki_scalar(expr: str) -> float:
        try:
            q = Q.prep_loki(expr, duration=duration)
            data = _proxy_get(
                f"{loki}/loki/api/v1/query_range",
                {
                    "query": q,
                    "start": start_ns,
                    "end": end_ns,
                    "limit": 100,
                    "direction": "backward",
                },
            )
            return _extract_scalar(data)
        except HTTPException as e:
            warnings.append(f"loki: {e.detail}")
            return 0.0

    def prom_scalar(expr: str) -> float:
        try:
            data = _proxy_get(f"{prom}/api/v1/query", {"query": expr})
            return _extract_scalar(data)
        except HTTPException as e:
            warnings.append(f"prometheus: {e.detail}")
            return 0.0

    spark_limit = _spark_limit(start, end, step)

    def prom_spark(expr: str, *, label: str = "spark") -> list[dict[str, float | int]]:
        try:
            data = _proxy_get(
                f"{prom}/api/v1/query_range",
                {"query": expr, "start": start, "end": end, "step": step},
            )
            for r in data.get("data", {}).get("result", []) or []:
                pts = Q.sparkline_points(
                    r.get("values") or [], limit=spark_limit
                )
                if pts:
                    return pts
        except HTTPException as e:
            warnings.append(f"{label}: {e.detail}")
        return []

    # Gateway totals — prefer agent decrypt Prom metrics; Loki as fallback.
    decrypt_total = prom_scalar(
        Q.prep_prom(Q.GATEWAY_DECRYPT_MSGS_TOTAL, node="gateway")
    )
    decrypt_rate = prom_scalar(
        Q.prep_prom(Q.GATEWAY_DECRYPT_MSGS_PER_SEC, node="gateway")
    )
    loki_total = int(loki_scalar(Q.GATEWAY_TOTAL_SENSOR_MSGS))
    loki_msgs_min = loki_scalar(Q.GATEWAY_MSGS_PER_MIN)
    total = int(decrypt_total) if decrypt_total > 0 else loki_total
    msgs_per_sec = (
        float(decrypt_rate)
        if decrypt_rate > 0
        else (float(loki_msgs_min) / 60.0 if loki_msgs_min else 0.0)
    )
    denied_prom = prom_scalar(Q.prep_prom(Q.GATEWAY_DENIED_PROM, node="gateway"))
    decrypt_fail = prom_scalar(
        Q.prep_prom(Q.GATEWAY_DECRYPT_FAIL_TOTAL, node="gateway")
    )
    ids_prom = prom_scalar(Q.prep_prom(Q.GATEWAY_IDS_PROM, node="gateway"))
    if denied_prom > 0:
        denied = int(denied_prom)
    else:
        denied = int(
            loki_scalar(Q.GATEWAY_DENIED_NODERED)
            + loki_scalar(Q.GATEWAY_DENIED_HAPROXY)
            + loki_scalar(Q.GATEWAY_DENIED_MOSQUITTO)
        )
    # Decrypt/schema fails are invalid messages; include them when the agent
    # denied counter is still ACL-only (pre-upgrade) or lagging.
    if decrypt_fail > denied:
        denied = int(decrypt_fail)
    if ids_prom > 0:
        ids_alerts = int(ids_prom)
    else:
        ids_alerts = int(loki_scalar(Q.GATEWAY_IDS_ALERTS))
    allowed_ips = int(prom_scalar(Q.GATEWAY_ALLOWED_IP_COUNT))

    def _prom_by_device(expr: str) -> dict[str, float]:
        out: dict[str, float] = {}
        try:
            data = _proxy_get(f"{prom}/api/v1/query", {"query": expr})
            for r in data.get("data", {}).get("result", []) or []:
                m = r.get("metric") or {}
                did = m.get("device_id") or m.get("deviceId")
                if not did:
                    continue
                val = r.get("value")
                if isinstance(val, (list, tuple)) and len(val) >= 2:
                    try:
                        out[str(did)] = float(val[1])
                    except (TypeError, ValueError):
                        continue
        except HTTPException as e:
            warnings.append(f"prom_by_device: {e.detail}")
        return out

    def _prom_spark_by_device(
        expr: str,
    ) -> dict[str, list[dict[str, float | int]]]:
        out: dict[str, list[dict[str, float | int]]] = {}
        try:
            data = _proxy_get(
                f"{prom}/api/v1/query_range",
                {"query": expr, "start": start, "end": end, "step": step},
            )
            for r in data.get("data", {}).get("result", []) or []:
                m = r.get("metric") or {}
                did = m.get("device_id") or m.get("deviceId")
                if not did:
                    continue
                spark = Q.sparkline_points(
                    r.get("values") or [], limit=spark_limit
                )
                if spark:
                    out[str(did)] = spark
        except HTTPException as e:
            warnings.append(f"prom_spark_by_device: {e.detail}")
        return out

    # Prom overlay for live MQTT client metadata.
    prom_connected: dict[str, dict[str, str]] = {}
    try:
        data = _proxy_get(
            f"{prom}/api/v1/query", {"query": Q.GATEWAY_CONNECTED_SENSORS}
        )
        for r in data.get("data", {}).get("result", []) or []:
            m = r.get("metric") or {}
            dev = m.get("device_id") or m.get("deviceId")
            if not dev:
                continue
            prom_connected[str(dev)] = {
                "client_id": str(m.get("client_id") or ""),
                "source_ip": str(m.get("source_ip") or ""),
            }
    except HTTPException as e:
        warnings.append(f"connected_sensors: {e.detail}")

    # Per-device Prom series (preferred over Loki).
    msgs_count_by_id = _prom_by_device(
        Q.prep_prom(Q.GATEWAY_MSGS_BY_DEVICE_PROM, node="gateway")
    )
    msgs_rate_by_id = _prom_by_device(
        Q.prep_prom(Q.GATEWAY_MSGS_BY_DEVICE_RATE_PROM, node="gateway")
    )
    denied_by_id = _prom_by_device(
        Q.prep_prom(Q.GATEWAY_DENIED_BY_DEVICE_PROM, node="gateway")
    )
    fail_by_id = _prom_by_device(
        Q.prep_prom(Q.GATEWAY_FAIL_BY_DEVICE_PROM, node="gateway")
    )
    for did, fail_n in fail_by_id.items():
        if float(fail_n or 0) > float(denied_by_id.get(did) or 0):
            denied_by_id[did] = float(fail_n)
    ids_by_id = _prom_by_device(
        Q.prep_prom(Q.GATEWAY_IDS_BY_DEVICE_PROM, node="gateway")
    )
    delay_latest_by_id = _prom_by_device(
        Q.prep_prom(Q.GATEWAY_DELAY_BY_DEVICE_PROM, node="gateway")
    )
    delay_sum_by_id = _prom_by_device(
        Q.prep_prom(Q.GATEWAY_DELAY_SUM_BY_DEVICE_PROM, node="gateway")
    )
    delay_samples_by_id = _prom_by_device(
        Q.prep_prom(Q.GATEWAY_DELAY_SAMPLES_BY_DEVICE_PROM, node="gateway")
    )
    msgs_chart_by_id = _prom_spark_by_device(
        Q.prep_prom(Q.GATEWAY_MSGS_BY_DEVICE_RATE_PROM, node="gateway")
    )
    delay_chart_by_id = _prom_spark_by_device(
        Q.prep_prom(Q.GATEWAY_DELAY_BY_DEVICE_PROM, node="gateway")
    )

    def _sane_delay_ms(v: Any) -> float | None:
        """Drop epoch-sized gauges from bad ts_ms (e.g. ~1.7e12)."""
        try:
            n = float(v)
        except (TypeError, ValueError):
            return None
        if n < 0 or n > 24 * 60 * 60 * 1000:
            return None
        return n

    def _sane_delay_total_ms(v: Any) -> float | None:
        """Cumulative processing delay may exceed 24h; reject only nonsense."""
        try:
            n = float(v)
        except (TypeError, ValueError):
            return None
        if n < 0 or n > 365 * 24 * 60 * 60 * 1000:
            return None
        return n

    def _sane_delay_points(
        pts: list[dict[str, float | int]],
    ) -> list[dict[str, float | int]]:
        out: list[dict[str, float | int]] = []
        for p in pts:
            n = _sane_delay_ms(p.get("v"))
            out.append(
                {
                    "t": int(p.get("t") or 0),
                    "v": 0.0 if n is None else float(n),
                }
            )
        return out

    delay_by_id: dict[str, dict[str, Any]] = {}
    delay_series_legacy: list[dict[str, Any]] = []
    for did, latest in delay_latest_by_id.items():
        latest_sane = _sane_delay_ms(latest)
        raw_pts = delay_chart_by_id.get(did) or (
            [{"t": end, "v": float(latest)}] if latest is not None else []
        )
        points = _sane_delay_points(raw_pts)
        spark = Q.point_values(points)
        entry = {
            "device_id": did,
            "latest": latest_sane,
            "sparkline": spark,
            "points": points,
        }
        delay_by_id[did] = entry
        delay_series_legacy.append(entry)

    # Loki delay fallback when Prom has no delay gauges yet.
    if not delay_by_id:
        try:
            q = Q.prep_loki(Q.GATEWAY_DELAY_BY_DEVICE, duration=duration)
            data = _proxy_get(
                f"{loki}/loki/api/v1/query_range",
                {
                    "query": q,
                    "start": start_ns,
                    "end": end_ns,
                    "limit": 500,
                    "direction": "backward",
                },
            )
            for stream in data.get("data", {}).get("result", []) or []:
                metric = stream.get("metric") or {}
                did = str(metric.get("deviceId") or metric.get("device_id") or "?")
                points = _sane_delay_points(
                    Q.sparkline_points(
                        stream.get("values") or [], limit=spark_limit
                    )
                )
                spark = Q.point_values(points)
                entry = {
                    "device_id": did,
                    "latest": spark[-1] if spark else None,
                    "sparkline": spark,
                    "points": points,
                }
                delay_by_id[did] = entry
                delay_series_legacy.append(entry)
        except HTTPException as e:
            warnings.append(f"delay: {e.detail}")

    # Loki per-device msg fallback when Prom device counters are empty.
    if not msgs_count_by_id and not msgs_rate_by_id:
        try:
            q = Q.prep_loki(Q.GATEWAY_MSGS_BY_DEVICE_COUNT, duration=duration)
            data = _proxy_get(
                f"{loki}/loki/api/v1/query_range",
                {
                    "query": q,
                    "start": start_ns,
                    "end": end_ns,
                    "limit": 500,
                    "direction": "backward",
                },
            )
            for stream in data.get("data", {}).get("result", []) or []:
                metric = stream.get("metric") or {}
                did = str(metric.get("deviceId") or metric.get("device_id") or "")
                if not did:
                    continue
                points = Q.sparkline_points(
                    stream.get("values") or [], limit=spark_limit
                )
                if points:
                    msgs_count_by_id[did] = float(points[-1]["v"])
                    msgs_chart_by_id[did] = points
        except HTTPException as e:
            warnings.append(f"msgs_by_device: {e.detail}")
        try:
            q = Q.prep_loki(Q.GATEWAY_MSGS_BY_DEVICE, duration=duration)
            data = _proxy_get(
                f"{loki}/loki/api/v1/query_range",
                {
                    "query": q,
                    "start": start_ns,
                    "end": end_ns,
                    "limit": 500,
                    "direction": "backward",
                },
            )
            for stream in data.get("data", {}).get("result", []) or []:
                metric = stream.get("metric") or {}
                did = str(metric.get("deviceId") or metric.get("device_id") or "")
                if not did:
                    continue
                points = Q.sparkline_points(
                    stream.get("values") or [], limit=spark_limit
                )
                if points:
                    msgs_rate_by_id[did] = float(points[-1]["v"])
                    msgs_chart_by_id.setdefault(did, points)
        except HTTPException as e:
            warnings.append(f"msgs_rate_by_device: {e.detail}")

    gateway_delay_spark: list[float] = []
    gateway_delay_points: list[dict[str, float | int]] = []
    gateway_delay_latest: float | None = None
    gateway_delay_total = _sane_delay_total_ms(
        prom_scalar(Q.prep_prom(Q.GATEWAY_DELAY_SUM_PROM, node="gateway"))
    )
    gateway_delay_samples = int(
        prom_scalar(Q.prep_prom(Q.GATEWAY_DELAY_SAMPLES_PROM, node="gateway"))
    )
    avg_delay = prom_scalar(Q.prep_prom(Q.GATEWAY_DELAY_AVG_PROM, node="gateway"))
    avg_sane = _sane_delay_ms(avg_delay)
    if avg_sane is not None:
        gateway_delay_latest = avg_sane
    if delay_series_legacy:
        lengths = [
            len(e.get("points") or e.get("sparkline") or [])
            for e in delay_series_legacy
        ]
        n = min(lengths) if lengths and min(lengths) > 0 else 0
        if n > 0:
            gateway_delay_spark = []
            gateway_delay_points = []
            for i in range(n):
                vals = [
                    (e.get("sparkline") or [])[i]
                    for e in delay_series_legacy
                    if len(e.get("sparkline") or []) > i
                ]
                avg_v = sum(vals) / len(vals) if vals else 0.0
                gateway_delay_spark.append(avg_v)
                ts = end
                for e in delay_series_legacy:
                    pts = e.get("points") or []
                    if len(pts) > i and isinstance(pts[i], dict):
                        ts = int(pts[i].get("t") or end)
                        break
                gateway_delay_points.append({"t": ts, "v": avg_v})
        if gateway_delay_latest is None:
            gateway_delay_latest = (
                gateway_delay_spark[-1] if gateway_delay_spark else None
            )

    decrypt_chart = prom_spark(
        Q.prep_prom(Q.GATEWAY_DECRYPT_MSGS_PER_SEC_RANGE, node="gateway"),
        label="decrypt_rate",
    )

    # Live catalog sync (best-effort): topics on the Pi missing from registry meta.
    catalog_topics: dict[str, dict[str, Any]] = {}
    if gw is not None:
        try:
            from .deps import open_ssh_for
            from provisioner.kafka_install import read_remote_catalog

            with open_ssh_for(state, gw) as ssh:
                cat = read_remote_catalog(ssh)
            raw_topics = cat.get("topics") or {}
            if isinstance(raw_topics, dict):
                for _key, rec in raw_topics.items():
                    if not isinstance(rec, dict):
                        continue
                    did = str(rec.get("device_id") or "").strip()
                    topic = str(rec.get("topic") or "").strip()
                    if did and topic:
                        catalog_topics[did] = rec
        except Exception as exc:  # noqa: BLE001 — Activities must not fail on SSH
            from .deps import sanitize_user_error

            # Never surface SSH key material (base64 bodies) in Activities UI.
            safe = sanitize_user_error(str(exc), fallback="SSH unavailable")
            warnings.append(f"kafka_catalog_sync: {safe}")

    # Registry devices are authoritative for the Activities sensor list.
    connected: list[dict[str, Any]] = []
    if gid:
        device_rows = registry.list_devices(gid)
        for row in device_rows:
            did = str(row["id"])
            meta = _device_meta(row)
            cat_rec = catalog_topics.get(did) or {}
            topic = (
                meta.get("kafka_topic")
                or cat_rec.get("topic")
                or kafka_topic_name(did)
            )
            retention = meta.get("kafka_retention_bytes")
            if retention is None:
                retention = cat_rec.get("retention_bytes")
            if retention is None:
                retention = DEFAULT_TOPIC_RETENTION_BYTES
            else:
                try:
                    retention = int(retention)
                except (TypeError, ValueError):
                    retention = DEFAULT_TOPIC_RETENTION_BYTES
            overlay = prom_connected.get(did) or {}
            delay = delay_by_id.get(did) or {}
            kafka_chart = msgs_chart_by_id.get(did) or []
            if not kafka_chart and len(device_rows) == 1 and decrypt_chart:
                kafka_chart = decrypt_chart
            delay_latest = delay.get("latest")
            if delay_latest is None and did in delay_latest_by_id:
                delay_latest = _sane_delay_ms(delay_latest_by_id[did])
            delay_total = _sane_delay_total_ms(delay_sum_by_id.get(did))
            delay_samples = int(delay_samples_by_id.get(did) or 0)
            connected.append(
                {
                    "device_id": did,
                    "ip": row.get("ip") or overlay.get("source_ip") or "",
                    "kafka_topic": str(topic),
                    "kafka_retention_bytes": int(retention),
                    "monitor_enabled": bool(int(row.get("monitor_enabled", 1) or 0)),
                    "is_fake": is_fake_meta(meta),
                    "client_id": overlay.get("client_id") or "",
                    "source_ip": overlay.get("source_ip") or (row.get("ip") or ""),
                    "metrics": {
                        "total_messages": int(msgs_count_by_id.get(did) or 0),
                        "messages_per_sec": round(
                            float(msgs_rate_by_id.get(did) or 0.0), 4
                        ),
                        "denied_publishes": int(denied_by_id.get(did) or 0),
                        "ids_detections": int(ids_by_id.get(did) or 0),
                        "delay_latest": delay_latest,
                        "delay_total": delay_total,
                        "delay_samples": delay_samples,
                    },
                    "charts": {
                        "kafka_messages": kafka_chart,
                        "delay": delay.get("points")
                        or delay_chart_by_id.get(did)
                        or [],
                    },
                }
            )
    elif prom_connected:
        # No registry gateway — fall back to Prom-only rows (legacy).
        for did, overlay in sorted(prom_connected.items()):
            delay = delay_by_id.get(did) or {}
            connected.append(
                {
                    "device_id": did,
                    "ip": overlay.get("source_ip") or "",
                    "kafka_topic": kafka_topic_name(did),
                    "kafka_retention_bytes": DEFAULT_TOPIC_RETENTION_BYTES,
                    "monitor_enabled": True,
                    "is_fake": False,
                    "client_id": overlay.get("client_id") or "",
                    "source_ip": overlay.get("source_ip") or "",
                    "metrics": {
                        "total_messages": int(msgs_count_by_id.get(did) or 0),
                        "messages_per_sec": round(
                            float(msgs_rate_by_id.get(did) or 0.0), 4
                        ),
                        "denied_publishes": int(denied_by_id.get(did) or 0),
                        "ids_detections": int(ids_by_id.get(did) or 0),
                        "delay_latest": delay.get("latest"),
                        "delay_total": _sane_delay_total_ms(
                            delay_sum_by_id.get(did)
                        ),
                        "delay_samples": int(delay_samples_by_id.get(did) or 0),
                    },
                    "charts": {
                        "kafka_messages": msgs_chart_by_id.get(did) or [],
                        "delay": delay.get("points") or [],
                    },
                }
            )

    delay_chart_out = gateway_delay_points or [
        {"t": start + i, "v": v}
        for i, v in enumerate(gateway_delay_spark[-spark_limit:])
    ]
    if gateway_delay_total is None and delay_sum_by_id:
        gateway_delay_total = _sane_delay_total_ms(sum(delay_sum_by_id.values()))
    if gateway_delay_samples <= 0 and delay_samples_by_id:
        gateway_delay_samples = int(sum(delay_samples_by_id.values()))

    denied_events = _fetch_agent_denied(gw, gateway_id=gid, limit=100)
    # Fill blank IPs from the registry / connected rows when the agent omits them.
    ip_by_device = {
        str(s.get("device_id") or ""): str(s.get("ip") or s.get("source_ip") or "")
        for s in connected
        if s.get("device_id")
    }
    for ev in denied_events:
        if not ev.get("source_ip"):
            ev["source_ip"] = ip_by_device.get(str(ev.get("device_id") or ""), "")
        if not ev.get("gateway_id") and gid:
            ev["gateway_id"] = str(gid)
    for s in connected:
        did = str(s.get("device_id") or "")
        s["denied_messages"] = [
            ev for ev in denied_events if str(ev.get("device_id") or "") == did
        ]

    return {
        "range": time_range,
        "time": _time_window_meta(time_range, start, end),
        "gateway_id": gid,
        "metrics": {
            "total_sensor_messages": total,
            "messages_per_sec": round(msgs_per_sec, 4),
            # Kept for older UI builds.
            "messages_per_minute": round(msgs_per_sec * 60.0, 3),
            "denied_publishes": denied,
            "ids_detections": ids_alerts,
            "allowed_ips": allowed_ips,
            "delay_latest": gateway_delay_latest,
            "delay_total": gateway_delay_total,
            "delay_samples": gateway_delay_samples,
            "delay_sparkline": Q.point_values(delay_chart_out)[-spark_limit:],
        },
        "charts": {
            "delay": delay_chart_out[-spark_limit:],
            "messages": decrypt_chart,
        },
        "connected_sensors": connected,
        "denied_messages": denied_events,
        "delay_by_device": delay_series_legacy,
        "kafka_catalog_topics": sorted(catalog_topics.keys()),
        "warnings": warnings,
    }


def _parse_step_s(step: str) -> int:
    """Parse a Prometheus step string like ``15s`` / ``2m`` into seconds."""
    raw = str(step).strip().lower()
    try:
        if raw.endswith("ms"):
            return max(1, int(raw[:-2]) // 1000 or 1)
        if raw.endswith("s"):
            return max(1, int(raw[:-1]))
        if raw.endswith("m"):
            return max(1, int(raw[:-1]) * 60)
        if raw.endswith("h"):
            return max(1, int(raw[:-1]) * 3600)
        return max(1, int(raw))
    except ValueError:
        return 60


def _range_window_s(range_s: str) -> tuple[int, int, str]:
    """Return (start_unix, end_unix, step) for Prometheus range queries."""
    start_ns, end_ns = _ns_window(range_s)
    start = start_ns // 1_000_000_000
    end = end_ns // 1_000_000_000
    span = max(end - start, 60)
    if span <= 300:  # 5m
        step = "5s"
    elif span <= 900:  # 15m
        step = "15s"
    elif span <= 3600:  # 1h
        step = "30s"
    elif span <= 10800:  # 3h
        step = "60s"
    elif span <= 21600:  # 6h
        step = "60s"
    elif span <= 86400:  # 12h–24h
        step = "2m"
    else:  # multi-day (e.g. 7d)
        step = "5m"
    return start, end, step


def _spark_limit(start: int, end: int, step: str) -> int:
    """Point budget for chart series (~2–6 minutes of wall for long ranges)."""
    step_s = _parse_step_s(step)
    span = max(int(end) - int(start), 1)
    return max(24, min(360, span // step_s + 2))


def _time_window_meta(range_s: str, start: int, end: int) -> dict[str, Any]:
    return {"range": range_s, "from": int(start), "to": int(end)}


def _container_label(metric: dict[str, Any]) -> str:
    raw = (
        metric.get("app")
        or metric.get("name")
        or metric.get("container_name")
        or metric.get("id")
        or "?"
    )
    name = str(raw).lstrip("/")
    if name.startswith("iot-"):
        name = name[4:]
    return name[:28] or "?"


_APP_STATUS_LABELS = {
    "agent": "Agent",
    "mqtt": "MQTT",
    "decrypt": "Decrypt",
    "shipper": "Shipper",
    "kafka": "Kafka",
}
# Stable Gateway Metrics Applications order (monolithic agent + local broker).
_CANONICAL_APPS = ("agent", "mqtt", "decrypt", "shipper", "kafka")


@router.get("/query/summaries/raspi")
def summary_raspi(
    node: str = Query(default="gateway"),
    job: str = Query(default="iot-gateway-agent"),
    range: str = Query(default="1h", alias="range"),
    state: AppState = Depends(get_state),
) -> dict[str, Any]:
    """Host (Raspi) metrics + chart series for native Monitoring Gateway Metric."""
    _, prom = _backend_urls(state)
    warnings: list[str] = []
    start, end, step = _range_window_s(range)
    spark_limit = _spark_limit(start, end, step)

    def prom_scalar(expr: str) -> float:
        try:
            q = Q.prep_prom(expr, node=node, job=job)
            data = _proxy_get(f"{prom}/api/v1/query", {"query": q})
            return _extract_scalar(data)
        except HTTPException as e:
            warnings.append(f"prometheus: {e.detail}")
            return 0.0

    def prom_max_scalar(expr: str) -> float:
        """Highest sample across a multi-series instant query (e.g. temps)."""
        try:
            q = Q.prep_prom(expr, node=node, job=job)
            data = _proxy_get(f"{prom}/api/v1/query", {"query": q})
            result = (data or {}).get("data", {}).get("result", []) or []
            best = 0.0
            found = False
            for r in result:
                try:
                    if "value" in r:
                        v = float(r["value"][1])
                    elif "values" in r and r["values"]:
                        v = float(r["values"][-1][1])
                    else:
                        continue
                except (TypeError, ValueError, IndexError, KeyError):
                    continue
                if not found or v > best:
                    best = v
                    found = True
            return best if found else 0.0
        except HTTPException as e:
            warnings.append(f"prometheus: {e.detail}")
            return 0.0

    def prom_spark(
        expr: str, *, scale: float = 1.0, label: str = "spark"
    ) -> list[dict[str, float | int]]:
        try:
            q = Q.prep_prom(expr, node=node, job=job)
            data = _proxy_get(
                f"{prom}/api/v1/query_range",
                {"query": q, "start": start, "end": end, "step": step},
            )
            for r in data.get("data", {}).get("result", []) or []:
                pts = Q.sparkline_points(
                    r.get("values") or [], limit=spark_limit
                )
                if scale != 1.0:
                    pts = [
                        {"t": int(p["t"]), "v": float(p["v"]) * scale}
                        for p in pts
                    ]
                return pts
        except HTTPException as e:
            warnings.append(f"{label}: {e.detail}")
        return []

    def prom_named_bars(expr: str, *, limit: int = 8, label: str = "bars") -> list[dict[str, Any]]:
        try:
            q = Q.prep_prom(expr, node=node, job=job)
            data = _proxy_get(f"{prom}/api/v1/query", {"query": q})
            rows: list[dict[str, Any]] = []
            for r in (data.get("data", {}).get("result", []) or [])[:limit]:
                metric = r.get("metric") or {}
                rows.append(
                    {
                        "name": _container_label(metric),
                        "value": round(_extract_scalar({"data": {"result": [r]}}), 3),
                    }
                )
            return rows
        except HTTPException as e:
            warnings.append(f"{label}: {e.detail}")
            return []

    cpu = prom_scalar(Q.RASPI_CPU_USAGE)
    cores = prom_scalar(Q.RASPI_CPU_CORES)
    mem_total = prom_scalar(Q.RASPI_MEM_TOTAL)
    mem_used = prom_scalar(Q.RASPI_MEM_USED)
    load1 = prom_scalar(Q.RASPI_LOAD1)
    fs_avail = prom_scalar(Q.RASPI_FS_AVAIL)
    fs_size = prom_scalar(Q.RASPI_FS_SIZE)
    up = prom_scalar(Q.RASPI_UP)
    temp_c = prom_max_scalar(Q.RASPI_TEMP_C)
    uptime_s = prom_scalar(Q.RASPI_UPTIME_S)
    swap_pct = prom_scalar(Q.RASPI_SWAP_PCT)
    iowait = prom_scalar(Q.RASPI_IOWAIT)
    procs_run = prom_scalar(Q.RASPI_PROCS_RUNNING)
    procs_blk = prom_scalar(Q.RASPI_PROCS_BLOCKED)

    cpu_spark = prom_spark(Q.RASPI_CPU_BUSY_PCT_RANGE, label="cpu_sparkline")
    mem_spark = prom_spark(Q.RASPI_MEM_USED_PCT_RANGE, label="mem_sparkline")
    load_spark = prom_spark(Q.RASPI_LOAD1, label="load_sparkline")
    fs_spark = prom_spark(Q.RASPI_FS_USED_PCT_RANGE, label="fs_sparkline")
    net_rx_spark = prom_spark(Q.RASPI_NET_RX_MBPS, label="net_rx_sparkline")
    net_tx_spark = prom_spark(Q.RASPI_NET_TX_MBPS, label="net_tx_sparkline")
    temp_spark = prom_spark(Q.RASPI_TEMP_C, label="temp_sparkline")

    # Applications (monolithic agent + Kafka) — prefer iotgw_app_*; fall back to legacy.
    app_status_rows = prom_named_bars(Q.RASPI_APP_UP, limit=12, label="app_status")
    if not app_status_rows:
        agent_up = prom_scalar(Q.RASPI_AGENT_UP)
        mqtt_up = prom_scalar(Q.RASPI_MQTT_UP)
        if agent_up or mqtt_up or up:
            app_status_rows = [
                {"name": "agent", "value": 1.0 if agent_up or up else 0.0},
                {"name": "mqtt", "value": 1.0 if mqtt_up else 0.0},
            ]
    by_app: dict[str, dict[str, Any]] = {}
    for r in app_status_rows:
        raw_id = str(r.get("name") or "?").lower()
        val = float(r.get("value") or 0)
        by_app[raw_id] = {
            "name": _APP_STATUS_LABELS.get(raw_id, raw_id),
            "id": raw_id,
            "up": val >= 0.5,
            "value": round(val, 3),
        }
    # Ensure Kafka appears even when an older scrape omitted iotgw_app_up{app="kafka"}.
    if "kafka" not in by_app:
        kafka_up = prom_scalar(Q.RASPI_KAFKA_UP)
        by_app["kafka"] = {
            "name": _APP_STATUS_LABELS["kafka"],
            "id": "kafka",
            "up": kafka_up >= 0.5,
            "value": round(float(kafka_up), 3),
        }
    app_status = []
    for app_id in _CANONICAL_APPS:
        if app_id in by_app:
            app_status.append(by_app.pop(app_id))
        else:
            app_status.append(
                {
                    "name": _APP_STATUS_LABELS.get(app_id, app_id),
                    "id": app_id,
                    "up": False,
                    "value": 0.0,
                }
            )
    # Keep any unexpected app labels after the canonical set.
    for extra in sorted(by_app.values(), key=lambda row: str(row.get("id") or "")):
        app_status.append(extra)
    apps_up = sum(1 for a in app_status if a["up"])
    apps_total = len(app_status) if app_status else int(prom_scalar(Q.RASPI_APPS_UP) or 0)

    decrypt_rate = prom_scalar(Q.RASPI_DECRYPT_MSGS_PER_MIN)
    shipper_rate = prom_scalar(Q.RASPI_SHIPPER_LINES_PER_MIN)
    kafka_produce_rate = prom_scalar(Q.RASPI_KAFKA_PRODUCE_PER_MIN)
    activity = [
        {"name": "Decrypt msgs/min", "value": round(decrypt_rate, 2)},
        {"name": "Loki lines/min", "value": round(shipper_rate, 2)},
        {"name": "Kafka produce/min", "value": round(kafka_produce_rate, 2)},
    ]

    app_cpu = prom_named_bars(Q.RASPI_APP_CPU, label="app_cpu")
    app_mem = prom_named_bars(Q.RASPI_APP_MEM_MIB, label="app_mem")
    # Legacy Docker scrapes only when agent app process metrics are absent.
    if not app_cpu:
        app_cpu = prom_named_bars(Q.RASPI_CONTAINER_CPU, label="container_cpu")
    if not app_mem:
        app_mem = prom_named_bars(Q.RASPI_CONTAINER_MEM_MIB, label="container_mem")

    return {
        "node": node,
        "job": job,
        "range": range,
        "time": _time_window_meta(range, start, end),
        "up": bool(up),
        "metrics": {
            "cpu_cores_busy": round(cpu, 3),
            "cpu_cores": int(cores) if cores else 0,
            "mem_used_bytes": int(mem_used),
            "mem_total_bytes": int(mem_total),
            "mem_used_pct": round((mem_used / mem_total) * 100, 1) if mem_total else 0.0,
            "load1": round(load1, 3),
            "fs_avail_bytes": int(fs_avail),
            "fs_size_bytes": int(fs_size),
            "fs_used_pct": (
                round((1 - fs_avail / fs_size) * 100, 1) if fs_size else 0.0
            ),
            "apps_up": apps_up,
            "apps_total": apps_total,
            "active_containers": apps_up,
            "temp_c": round(temp_c, 1) if temp_c else None,
            "uptime_s": int(uptime_s) if uptime_s else 0,
            "swap_pct": round(swap_pct, 1) if swap_pct else 0.0,
            "iowait_cores": round(iowait, 3) if iowait else 0.0,
            "procs_running": int(procs_run) if procs_run else 0,
            "procs_blocked": int(procs_blk) if procs_blk else 0,
        },
        # Legacy float sparkline for older UI builds.
        "cpu_sparkline_pct": Q.point_values(cpu_spark),
        "charts": {
            "cpu_pct": cpu_spark,
            "mem_used_pct": mem_spark,
            "load1": load_spark,
            "fs_used_pct": fs_spark,
            "net_rx_mbps": net_rx_spark,
            "net_tx_mbps": net_tx_spark,
            "temp_c": temp_spark,
        },
        "applications": {
            "status": app_status,
            "activity": activity,
            "cpu": app_cpu,
            "mem_mib": app_mem,
        },
        # Kept for older UI builds; prefer ``applications``.
        "containers": {
            "cpu": app_cpu,
            "mem_mib": app_mem,
        },
        "warnings": warnings,
    }


@router.get("/query/summaries/sensors")
def summary_sensors(
    gateway_id: Optional[str] = None,
    show_all: bool = False,
    range: str = Query(default="1h", alias="range"),
    state: AppState = Depends(get_state),
    registry: Registry = Depends(get_registry),
) -> dict[str, Any]:
    """Sensors Reading summary; filters to monitor_enabled=1 when devices exist."""
    loki, _ = _backend_urls(state)
    start_ns, end_ns = _ns_window(range)
    allowed = _monitored_ids(registry, gateway_id, show_all=show_all)
    warnings: list[str] = []

    def loki_range(expr: str) -> Any:
        q = Q.prep_loki(expr, duration=range)
        return _proxy_get(
            f"{loki}/loki/api/v1/query_range",
            {
                "query": q,
                "start": start_ns,
                "end": end_ns,
                "limit": 1000,
                "direction": "backward",
            },
        )

    stages: list[dict[str, Any]] = []
    try:
        data = loki_range(Q.SENSORS_STAGE)
        result = Q.filter_series_by_device(
            data.get("data", {}).get("result", []) or [],
            allowed=allowed,
        )
        for stream in result:
            metric = stream.get("metric") or {}
            stage = metric.get("stage", "Unknown")
            values = stream.get("values") or []
            if values:
                stage = values[-1][1]
            stages.append(
                {
                    "device_id": metric.get("deviceId") or "?",
                    "stage": stage,
                }
            )
    except HTTPException as e:
        warnings.append(f"stages: {e.detail}")

    def series_sparks(expr: str, label: str) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        try:
            data = loki_range(expr)
            result = Q.filter_series_by_device(
                data.get("data", {}).get("result", []) or [],
                allowed=allowed,
            )
            for stream in result:
                metric = stream.get("metric") or {}
                spark = Q.sparkline_floats(stream.get("values") or [])
                out.append(
                    {
                        "device_id": metric.get("deviceId") or "?",
                        "series": label,
                        "latest": spark[-1] if spark else None,
                        "sparkline": spark,
                    }
                )
        except HTTPException as e:
            warnings.append(f"{label}: {e.detail}")
        return out

    temps = (
        series_sparks(Q.SENSORS_TEMP_ZONE1, "Zone 1")
        + series_sparks(Q.SENSORS_TEMP_ZONE2, "Zone 2")
        + series_sparks(Q.SENSORS_TEMP_ZONE3, "Zone 3")
        + series_sparks(Q.SENSORS_TEMP_CHAMBER, "Chamber")
    )
    pressures = series_sparks(Q.SENSORS_PRESSURE_CHAMBER, "Chamber")

    return {
        "range": range,
        "gateway_id": gateway_id,
        "show_all": show_all,
        "filter_active": allowed is not None,
        "monitored_device_ids": sorted(allowed) if allowed is not None else [],
        "stages": stages,
        "temperatures": temps,
        "pressures": pressures,
        "warnings": warnings,
    }
