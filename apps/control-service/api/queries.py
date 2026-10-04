"""Golden PromQL / LogQL expressions mirroring Streamlit dashboards.

Used by /api/v1/query/summaries/* and golden tests — keep in sync with
monitoring/build/streamlit/modules/dashboards/{gateway,raspi,sensors}.py.
"""

from __future__ import annotations

import re
from typing import Optional

# ── Gateway Activities (gateway.py) ──────────────────────────────────────────
GATEWAY_TOTAL_SENSOR_MSGS = (
    'sum(count_over_time({container="iot-nodered", event_type="sensor_data"}[{range}]))'
)
GATEWAY_MSGS_PER_MIN = (
    'sum(rate({container="iot-nodered", event_type="sensor_data"}[{range}])) * 60'
)
GATEWAY_DENIED_NODERED = (
    'count_over_time({container="iot-nodered", event_type=~"denied_.*"}[{range}])'
)
GATEWAY_DENIED_HAPROXY = (
    'count_over_time({container="iot-haproxy"} |~ '
    '"mqtts_frontend|handshake|ssl|verify|certificate|c_verify=[1-9]|SC--|C--|reject|NOSRV" '
    "[{range}])"
)
GATEWAY_DENIED_MOSQUITTO = (
    'count_over_time({container="iot-mosquitto"} |~ "Denied PUBLISH" [{range}])'
)
GATEWAY_IDS_ALERTS = (
    'count_over_time({job="ids-alerts", event_type="ids_alert"}[{range}])'
)
GATEWAY_ALLOWED_IP_COUNT = "allowed_ip_count"
GATEWAY_CONNECTED_SENSORS = "mqtt_connected_sensor"
GATEWAY_DELAY_BY_DEVICE = (
    'avg_over_time({container="iot-nodered", event_type="sensor_data"} '
    "| json | unwrap delay [5m]) by (deviceId)"
)

# ── Raspi / Host (raspi.py) ──────────────────────────────────────────────────
RASPI_CPU_USAGE = (
    'count(count(node_cpu_seconds_total{instance="$node",job="$job"}) by (cpu)) '
    '* (1 - avg(rate(node_cpu_seconds_total{instance="$node",job="$job",mode="idle"}[30s])))'
)
RASPI_CPU_CORES = (
    'count(count(node_cpu_seconds_total{instance="$node",job="$job"}) by (cpu))'
)
RASPI_MEM_TOTAL = 'node_memory_MemTotal_bytes{instance="$node",job="$job"}'
RASPI_MEM_USED = (
    'node_memory_MemTotal_bytes{instance="$node",job="$job"}'
    ' - node_memory_MemAvailable_bytes{instance="$node",job="$job"}'
)
RASPI_LOAD1 = 'node_load1{instance="$node",job="$job"}'
RASPI_FS_AVAIL = (
    'node_filesystem_avail_bytes{instance="$node",job="$job",mountpoint="/"}'
)
RASPI_FS_SIZE = (
    'node_filesystem_size_bytes{instance="$node",job="$job",mountpoint="/"}'
)
RASPI_ACTIVE_CONTAINERS = (
    'count(container_last_seen{instance="$node",job="$job",name=~".+"} > (time() - 120))'
)
RASPI_UP = 'up{instance="$node",job="$job"}'

# ── Sensors (sensors.py) ─────────────────────────────────────────────────────
SENSORS_STAGE = """last_over_time(
  {event_type="sensor_data"}
  | json
  | label_format stage="{{.payload_process_parameters_sinteringStage_value}}"
  [5m]
) by (deviceId)"""

SENSORS_TEMP_ZONE1 = (
    'max_over_time({event_type="sensor_data"} | json '
    "| unwrap payload_process_parameters_temperatureZone1_value [5m]) by (deviceId)"
)
SENSORS_TEMP_ZONE2 = (
    'max_over_time({event_type="sensor_data"} | json '
    "| unwrap payload_process_parameters_temperatureZone2_value [5m]) by (deviceId)"
)
SENSORS_TEMP_ZONE3 = (
    'max_over_time({event_type="sensor_data"} | json '
    "| unwrap payload_process_parameters_temperatureZone3_value [5m]) by (deviceId)"
)
SENSORS_TEMP_CHAMBER = (
    'max_over_time({event_type="sensor_data"} | json '
    "| unwrap payload_process_parameters_temperatureChamber_value [5m]) by (deviceId)"
)
SENSORS_PRESSURE_CHAMBER = (
    'max_over_time({event_type="sensor_data"} | json '
    "| unwrap payload_process_parameters_pressureChamber_value [5m]) by (deviceId)"
)


def prep_loki(expr: str, *, duration: str = "1h") -> str:
    expr = expr.replace("\r\n", "\n").replace("[{range}]", f"[{duration}]")
    expr = expr.replace("$__range", duration)
    expr = re.sub(r"\[\$__interval\]", "[5m]", expr)
    return expr


def prep_prom(expr: str, *, node: str = "gateway", job: str = "node") -> str:
    expr = expr.replace("\r\n", "\n")
    expr = expr.replace("$node", node).replace("$job", job)
    expr = re.sub(r"\[\$__rate_interval\]", "[5m]", expr)
    expr = re.sub(r"\[\$__interval\]", "[5m]", expr)
    return expr


def device_id_filter_logql(device_ids: list[str]) -> str:
    """Build a Loki label matcher for deviceId when filtering monitored devices."""
    if not device_ids:
        return ""
    # Escape regex special chars in ids; join with |.
    parts = [re.escape(d) for d in device_ids]
    return f', deviceId=~"{"|".join(parts)}"'


def filter_series_by_device(
    result: list[dict],
    *,
    allowed: Optional[set[str]],
    label_keys: tuple[str, ...] = ("deviceId", "device_id"),
) -> list[dict]:
    """Drop Prometheus/Loki series whose device label is not in ``allowed``.

    When ``allowed`` is None (no registry filter), return ``result`` unchanged.
    """
    if allowed is None:
        return result
    out: list[dict] = []
    for series in result:
        metric = series.get("metric") or series.get("stream") or {}
        if not isinstance(metric, dict):
            continue
        did = None
        for k in label_keys:
            if metric.get(k):
                did = str(metric[k])
                break
        if did is None or did in allowed:
            out.append(series)
    return out
