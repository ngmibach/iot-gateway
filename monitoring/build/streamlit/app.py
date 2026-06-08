import streamlit as st
import requests
import pandas as pd
from datetime import datetime, timedelta, time as dtime
import plotly.express as px
import plotly.graph_objects as go
import json
import re

st.set_page_config(
    page_title="IoT Gateway Monitor",
    layout="wide",
    initial_sidebar_state="expanded"
)

st.markdown("""
<style>
    /* Navigation pills */
    div[data-testid="stRadio"] label {
        font-size: 14px;
    }
    /* Metric cards */
    div[data-testid="metric-container"] {
        background-color: #1e1e2e;
        border: 1px solid #313244;
        border-radius: 8px;
        padding: 12px;
    }
    /* Section headers */
    .section-header {
        background: linear-gradient(90deg, #1e3a5f 0%, #0f2942 100%);
        color: #cdd6f4;
        padding: 8px 16px;
        border-radius: 6px;
        margin: 16px 0 8px 0;
        font-size: 14px;
        font-weight: 600;
        letter-spacing: 0.5px;
        border-left: 4px solid #89b4fa;
    }
    /* Status badge */
    .status-ok { color: #a6e3a1; font-weight: bold; }
    .status-err { color: #f38ba8; font-weight: bold; }
    /* Colored sidebar headings */
    .sidebar-heading {
        font-size: 0.95rem;
        font-weight: 600;
        margin: 4px 0 6px 0;
        letter-spacing: 0.3px;
    }
</style>
""", unsafe_allow_html=True)

# ───────────────────────── Configuration ─────────────────────────
LOKI_URL = "http://172.17.0.1:3100"
PROMETHEUS_URL = "http://172.17.0.1:9090"

# ───────────────────────── Sidebar ───────────────────────────────
with st.sidebar:
    st.markdown('<p class="sidebar-heading" style="color:#89dceb; font-size:1.1rem;">IoT Gateway Monitor</p>', unsafe_allow_html=True)
    st.markdown("---")

    # ── Dashboard Navigation ──
    st.markdown('<p class="sidebar-heading" style="color:#89b4fa;">Dashboard</p>', unsafe_allow_html=True)
    dashboard = st.radio(
        "dashboard_select",
        options=[
            "Gateway Activities",
            "Raspberry PI Metrics",
            "Sensors Reading",
        ],
        label_visibility="collapsed",
    )

    st.markdown("---")

    # ── Date & Time Range ──
    st.markdown('<p class="sidebar-heading" style="color:#b4befe;">Date & Time Range</p>', unsafe_allow_html=True)
    selected_date = st.date_input("Date", value=datetime.now().date())

    time_mode = st.radio("Range Mode", ["Full Day", "Custom Hours"], horizontal=True)
    if time_mode == "Full Day":
        start_dt = datetime.combine(selected_date, dtime(0, 0, 0))
        end_dt = datetime.combine(selected_date, dtime(23, 59, 59))
    else:
        c1, c2 = st.columns(2)
        with c1:
            sh = st.time_input("From", value=dtime(0, 0))
        with c2:
            eh = st.time_input("To", value=dtime(23, 59))
        start_dt = datetime.combine(selected_date, sh)
        end_dt = datetime.combine(selected_date, eh)

    st.caption(f"▶ {start_dt.strftime('%Y-%m-%d %H:%M')}")
    st.caption(f"◀ {end_dt.strftime('%Y-%m-%d %H:%M')}")

    # ── Node config (Raspberry PI only) ──
    if "Raspberry" in dashboard:
        st.markdown("---")
        st.markdown('<p class="sidebar-heading" style="color:#a6adc8;">Prometheus Node</p>', unsafe_allow_html=True)
        node_instance = st.text_input("Instance", "localhost:9100")
        job_name = st.text_input("Job", "node")
    else:
        node_instance = "localhost:9100"
        job_name = "node"

    st.markdown("---")
    st.caption("Loki: " + LOKI_URL)
    st.caption("Prometheus: " + PROMETHEUS_URL)

# ───────────────────────── Time helpers ──────────────────────────
start_ns = int(start_dt.timestamp() * 1e9)
end_ns   = int(end_dt.timestamp() * 1e9)
start_s  = int(start_dt.timestamp())
end_s    = int(end_dt.timestamp())

delta = end_dt - start_dt
total_hours = max(1, int(delta.total_seconds() / 3600) + 1)
if delta.days >= 1:
    duration = f"{delta.days + 1}d"
elif total_hours >= 1:
    duration = f"{total_hours}h"
else:
    duration = "1h"

# Auto step for prometheus (aim ~300 data points)
prom_step = max(60, int(delta.total_seconds() / 300))
prom_step_str = f"{prom_step}s"

# ───────────────────────── Query helpers ─────────────────────────
def _prep_loki(expr: str) -> str:
    expr = expr.replace("\r\n", "\n").replace("[$__range]", f"[{duration}]")
    expr = re.sub(r'\[\$__interval\]', "[5m]", expr)
    return expr

def _prep_prom(expr: str) -> str:
    expr = expr.replace("\r\n", "\n")
    expr = expr.replace("$node", node_instance).replace("$job", job_name)
    expr = re.sub(r'\[\$__rate_interval\]', "[5m]", expr)
    expr = re.sub(r'\[\$__interval\]', "[5m]", expr)
    return expr

@st.cache_data(ttl=30, show_spinner=False)
def query_loki(query: str, limit: int = 1000):
    try:
        r = requests.get(
            f"{LOKI_URL}/loki/api/v1/query_range",
            params={"query": query, "start": start_ns, "end": end_ns,
                    "limit": limit, "direction": "backward"},
            timeout=20,
        )
        if r.status_code != 200:
            return None
        return r.json()
    except Exception:
        return None

@st.cache_data(ttl=30, show_spinner=False)
def query_prometheus(query: str):
    try:
        r = requests.get(
            f"{PROMETHEUS_URL}/api/v1/query_range",
            params={"query": query, "start": start_s, "end": end_s, "step": prom_step_str},
            timeout=20,
        )
        if r.status_code != 200:
            return None
        return r.json()
    except Exception:
        return None

@st.cache_data(ttl=30, show_spinner=False)
def query_prometheus_instant(query: str):
    try:
        r = requests.get(
            f"{PROMETHEUS_URL}/api/v1/query",
            params={"query": query, "time": end_s},
            timeout=20,
        )
        if r.status_code != 200:
            return None
        return r.json()
    except Exception:
        return None

# ───────────────────────── Data-frame helpers ────────────────────
def _extract_scalar(data) -> float:
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
    except Exception:
        pass
    return 0.0

def loki_to_df(data, legend_key: str = "deviceId") -> pd.DataFrame | None:
    """Convert Loki metric query result to tidy DataFrame."""
    if not data:
        return None
    result = data.get("data", {}).get("result", [])
    if not result:
        return None
    rows = []
    for stream in result:
        label = stream["metric"].get(legend_key) or str(stream["metric"])
        for ts, val in stream.get("values", []):
            try:
                rows.append({"time": pd.Timestamp(datetime.fromtimestamp(float(ts))),
                             "value": float(val), "series": label})
            except Exception:
                pass
    return pd.DataFrame(rows) if rows else None

def prom_to_df(data, legends: list[str] | None = None) -> pd.DataFrame | None:
    """Convert Prometheus range query result to tidy DataFrame."""
    if not data:
        return None
    result = data.get("data", {}).get("result", [])
    if not result:
        return None
    rows = []
    for i, series in enumerate(result):
        if legends and i < len(legends):
            label = legends[i]
        else:
            m = series.get("metric", {})
            label = m.get("mode") or m.get("device") or m.get("mountpoint") or str(m)
        for ts, val in series.get("values", []):
            try:
                if val != "NaN":
                    rows.append({"time": pd.Timestamp(datetime.fromtimestamp(int(ts))),
                                 "value": float(val), "series": label})
            except Exception:
                pass
    return pd.DataFrame(rows) if rows else None

def loki_logs_to_df(data) -> pd.DataFrame | None:
    """Convert Loki log stream result to DataFrame."""
    if not data:
        return None
    streams = data.get("data", {}).get("result", [])
    rows = []
    for stream in streams:
        for ts, line in stream.get("values", []):
            try:
                rows.append({"time": pd.Timestamp(datetime.fromtimestamp(int(ts) / 1e9)), "log": line})
            except Exception:
                pass
    if not rows:
        return None
    df = pd.DataFrame(rows).sort_values("time", ascending=False).reset_index(drop=True)
    return df

# ───────────────────────── Chart helpers ─────────────────────────
def _no_data_placeholder(label: str):
    st.info(f"No data — {label}")

def line_chart(df: pd.DataFrame | None, title: str, y_label: str = "Value",
               height: int = 280, unit_scale: float = 1.0):
    if df is None or df.empty:
        _no_data_placeholder(title)
        return
    if unit_scale != 1.0:
        df = df.copy()
        df["value"] = df["value"] * unit_scale

    # Choose tick format based on the width of the selected window
    span_hours = (end_dt - start_dt).total_seconds() / 3600
    if span_hours <= 1:
        tick_fmt = "%H:%M:%S"
    elif span_hours <= 24:
        tick_fmt = "%H:%M"
    else:
        tick_fmt = "%m-%d %H:%M"

    # Dynamically compute bottom margin so legend rows never overlap the chart.
    # Estimate ~4 series per row for the horizontal legend; each row ~24 px.
    n_series = df["series"].nunique()
    legend_rows = max(1, -(-n_series // 4))   # ceiling division
    bottom_margin = 20 + legend_rows * 26     # 26 px per row + small pad

    fig = px.line(df, x="time", y="value", color="series",
                  title=title, labels={"value": y_label, "time": ""})
    fig.update_layout(
        # Add legend height to total figure height so the plot area stays tall
        height=height + bottom_margin,
        margin=dict(l=10, r=10, t=50, b=bottom_margin),
        # Title anchored firmly at the top — completely separate from the legend
        title=dict(
            text=title,
            x=0.5,
            xanchor="center",
            yanchor="top",
            font=dict(size=14),
            pad=dict(b=8),
        ),
        # Legend placed below the chart area, never above the title
        legend=dict(
            orientation="h",
            yanchor="top",
            y=-0.02,          # just below the x-axis, not above the chart
            xanchor="left",
            x=0,
            font=dict(size=11),
            tracegroupgap=4,
        ),
        plot_bgcolor="#1e1e2e",
        paper_bgcolor="#1e1e2e",
        font_color="#cdd6f4",
    )
    fig.update_xaxes(
        range=[start_dt, end_dt],          # ← pin to selected window
        tickformat=tick_fmt,               # ← sensible tick labels
        gridcolor="#313244",
        showgrid=True,
    )
    fig.update_yaxes(gridcolor="#313244")
    st.plotly_chart(fig, use_container_width=True)

def bar_chart(df: pd.DataFrame | None, title: str, y_label: str = "Count",
              height: int = 280):
    if df is None or df.empty:
        _no_data_placeholder(title)
        return
    fig = px.bar(df, x="series", y="value", title=title,
                 labels={"value": y_label, "series": "Device"})
    fig.update_layout(height=height, margin=dict(l=10, r=10, t=40, b=10),
                      plot_bgcolor="#1e1e2e", paper_bgcolor="#1e1e2e",
                      font_color="#cdd6f4")
    fig.update_xaxes(gridcolor="#313244")
    fig.update_yaxes(gridcolor="#313244")
    st.plotly_chart(fig, use_container_width=True)

def gauge_chart(value: float, title: str, min_val: float = 0,
                max_val: float = 100, unit: str = "%", height: int = 200):
    color = "#a6e3a1" if value < 70 else "#f9e2af" if value < 90 else "#f38ba8"
    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=value,
        title={"text": title, "font": {"color": "#cdd6f4", "size": 13}},
        number={"suffix": unit, "font": {"color": "#cdd6f4"}},
        gauge={
            "axis": {"range": [min_val, max_val], "tickcolor": "#cdd6f4"},
            "bar": {"color": color},
            "bgcolor": "#313244",
            "bordercolor": "#45475a",
            "steps": [
                {"range": [min_val, max_val * 0.7], "color": "#1e1e2e"},
                {"range": [max_val * 0.7, max_val * 0.9], "color": "#2a2a3e"},
                {"range": [max_val * 0.9, max_val], "color": "#3a1e2e"},
            ],
        },
    ))
    fig.update_layout(height=height, margin=dict(l=20, r=20, t=50, b=10),
                      paper_bgcolor="#1e1e2e", font_color="#cdd6f4")
    st.plotly_chart(fig, use_container_width=True)

def section(label: str):
    st.markdown(f'<div class="section-header">{label}</div>', unsafe_allow_html=True)

# ═══════════════════════════════════════════════════════════════════
#  DASHBOARD 1 — GATEWAY ACTIVITIES
# ═══════════════════════════════════════════════════════════════════
def render_gateway():
    st.markdown('<h1 style="color:#89b4fa;">IoT Sensor Gateway — Activities</h1>', unsafe_allow_html=True)
    st.caption(f"Date: **{selected_date}** · Range: **{duration}** · {start_dt.strftime('%H:%M')} → {end_dt.strftime('%H:%M')}")

    # ── Overview Metrics ──────────────────────────────────────────
    section("Overview")
    c1, c2, c3, c4 = st.columns(4)

    with st.spinner("Loading metrics…"):
        # Total sensor messages
        q = _prep_loki(f'sum(count_over_time({{container="iot-nodered", event_type="sensor_data"}}[$__range]))')
        d = query_loki(q)
        total_msgs = int(_extract_scalar(d)) if d else 0

        # Messages/min
        q = _prep_loki(f'sum(rate({{container="iot-nodered", event_type="sensor_data"}}[$__range])) * 60')
        d = query_loki(q)
        msgs_min = _extract_scalar(d) if d else 0.0

        # Denied publishes
        q = _prep_loki(f'count_over_time({{container="iot-mosquitto"}} |~ "Denied PUBLISH"[$__range])')
        d = query_loki(q)
        denied = int(_extract_scalar(d)) if d else 0

        # Active sensors
        q = _prep_loki(f'sum by (deviceId) (count_over_time({{container="iot-nodered", event_type="sensor_data"}}[$__range]))')
        d = query_loki(q)
        active = len(d["data"]["result"]) if d and d.get("data", {}).get("result") else 0

    c1.metric("Total Sensor Messages", f"{total_msgs:,}")
    c2.metric("Messages / Minute", f"{msgs_min:.2f}")
    c3.metric("Denied Publishes", f"{denied:,}")
    c4.metric("Active Sensors", active)

    # ── Transmission Activity ─────────────────────────────────────
    section("Transmission Activity")
    tab1, tab2 = st.tabs(["Sensor Message Rate", "Messages per Sensor"])

    with tab1:
        q = _prep_loki('rate({container="iot-nodered", event_type="sensor_data"}[$__range])')
        d = query_loki(q)
        df = loki_to_df(d)
        line_chart(df, "Sensor Message Rate (msg/s)", y_label="Rate (msg/s)")

    with tab2:
        q = _prep_loki('sum(count_over_time({container="iot-nodered", event_type="sensor_data"}[$__range])) by (deviceId)')
        d = query_loki(q)
        if d and d.get("data", {}).get("result"):
            agg = pd.DataFrame([
                {"series": r["metric"].get("deviceId", "unknown"),
                 "value": _extract_scalar(r)}
                for r in d["data"]["result"]
            ])
            bar_chart(agg, "Messages per Sensor (selected range)", y_label="Message Count")
        else:
            _no_data_placeholder("Messages per Sensor")

    # ── Latest Readings & Logs ────────────────────────────────────
    section("Latest Readings & Logs")
    col_a, col_b = st.columns([1, 1])

    with col_a:
        st.markdown('<span style="font-weight:700;color:#89b4fa;">Latest Sensor Readings</span>', unsafe_allow_html=True)
        q = _prep_loki('{container="iot-nodered", event_type="sensor_data"}')
        d = query_loki(q, limit=200)
        df_logs = loki_logs_to_df(d)
        if df_logs is not None:
            st.dataframe(df_logs, use_container_width=True, height=320,
                         column_config={"time": st.column_config.DatetimeColumn("Time", format="HH:mm:ss")})
        else:
            _no_data_placeholder("Sensor readings")

    with col_b:
        st.markdown('<span style="font-weight:700;color:#89dceb;">Recent MQTT Events</span>', unsafe_allow_html=True)
        q = _prep_loki('{container="iot-mosquitto"} |~ "New client|PUBLISH|Denied|DISCONNECT"')
        d = query_loki(q, limit=200)
        df_mqtt = loki_logs_to_df(d)
        if df_mqtt is not None:
            st.dataframe(df_mqtt, use_container_width=True, height=320,
                         column_config={"time": st.column_config.DatetimeColumn("Time", format="HH:mm:ss")})
        else:
            _no_data_placeholder("MQTT events")


# ═══════════════════════════════════════════════════════════════════
#  DASHBOARD 2 — RASPBERRY PI METRICS
# ═══════════════════════════════════════════════════════════════════
def render_raspi():
    st.markdown('<h1 style="color:#f38ba8;">Raspberry PI — System Metrics</h1>', unsafe_allow_html=True)
    st.caption(f"Node: **{node_instance}** · Job: **{job_name}** · Date: **{selected_date}** · {start_dt.strftime('%H:%M')} → {end_dt.strftime('%H:%M')}")

    # ── Quick Overview Gauges ─────────────────────────────────────
    section("Quick Overview — CPU / Memory / Disk")

    def prom_scalar(expr):
        d = query_prometheus_instant(_prep_prom(expr))
        if not d:
            return 0.0
        result = d.get("data", {}).get("result", [])
        if not result:
            return 0.0
        try:
            return float(result[0]["value"][1])
        except Exception:
            return 0.0

    cpu_pct = prom_scalar(
        '100 * (1 - avg(rate(node_cpu_seconds_total{mode="idle",instance="$node",job="$job"}[5m])))'
    )
    sys_load = prom_scalar(
        'scalar(node_load1{instance="$node",job="$job"}) * 100 / count(count(node_cpu_seconds_total{instance="$node",job="$job"}) by (cpu))'
    )
    ram_pct = prom_scalar(
        '100 * (1 - (node_memory_MemAvailable_bytes{instance="$node",job="$job"} / node_memory_MemTotal_bytes{instance="$node",job="$job"}))'
    )
    swap_pct = prom_scalar(
        '(node_memory_SwapTotal_bytes{instance="$node",job="$job"} > bool 0) * ((node_memory_SwapTotal_bytes{instance="$node",job="$job"} - node_memory_SwapFree_bytes{instance="$node",job="$job"}) / node_memory_SwapTotal_bytes{instance="$node",job="$job"} * 100)'
    )
    fs_pct = prom_scalar(
        '100 * ((node_filesystem_size_bytes{instance="$node",job="$job",mountpoint="/",fstype!="rootfs"} - node_filesystem_avail_bytes{instance="$node",job="$job",mountpoint="/",fstype!="rootfs"}) / node_filesystem_size_bytes{instance="$node",job="$job",mountpoint="/",fstype!="rootfs"})'
    )

    g1, g2, g3, g4, g5 = st.columns(5)
    with g1: gauge_chart(round(cpu_pct, 1), "CPU Busy")
    with g2: gauge_chart(round(sys_load, 1), "Sys Load (1m)")
    with g3: gauge_chart(round(ram_pct, 1), "RAM Used")
    with g4: gauge_chart(round(swap_pct, 1), "SWAP Used")
    with g5: gauge_chart(round(fs_pct, 1), "Root FS Used")

    # Stats row
    s1, s2, s3, s4, s5 = st.columns(5)
    cores = prom_scalar('count(count(node_cpu_seconds_total{instance="$node",job="$job"}) by (cpu))')
    ram_total = prom_scalar('node_memory_MemTotal_bytes{instance="$node",job="$job"}')
    swap_total = prom_scalar('node_memory_SwapTotal_bytes{instance="$node",job="$job"}')
    fs_total = prom_scalar('node_filesystem_size_bytes{instance="$node",job="$job",mountpoint="/",fstype!="rootfs"}')
    uptime = prom_scalar('node_time_seconds{instance="$node",job="$job"} - node_boot_time_seconds{instance="$node",job="$job"}')

    s1.metric("CPU Cores", int(cores) if cores else "—")
    s2.metric("RAM Total", f"{ram_total/1e9:.1f} GB" if ram_total else "—")
    s3.metric("SWAP Total", f"{swap_total/1e6:.0f} MB" if swap_total else "—")
    s4.metric("RootFS Total", f"{fs_total/1e9:.1f} GB" if fs_total else "—")
    s5.metric("Uptime", f"{uptime/86400:.1f} d" if uptime else "—")

    # ── CPU ───────────────────────────────────────────────────────
    section("CPU Usage")
    tab_cpu1, tab_cpu2 = st.tabs(["Basic", "Detailed"])

    with tab_cpu1:
        legends = ["Busy System", "Busy User", "Busy Iowait", "Busy IRQs", "Busy Other", "Idle"]
        exprs = [
            'avg(rate(node_cpu_seconds_total{instance="$node",job="$job", mode="system"}[$__rate_interval]))',
            'avg(rate(node_cpu_seconds_total{instance="$node",job="$job", mode="user"}[$__rate_interval]))',
            'avg(rate(node_cpu_seconds_total{instance="$node",job="$job", mode="iowait"}[$__rate_interval]))',
            'avg(sum without(mode) (rate(node_cpu_seconds_total{instance="$node",job="$job", mode=~".*irq"}[$__rate_interval])))',
            'avg(rate(node_cpu_seconds_total{instance="$node",job="$job", mode="idle"}[$__rate_interval]))',
        ]
        dfs = []
        for expr, leg in zip(exprs, legends):
            d = query_prometheus(_prep_prom(expr))
            df = prom_to_df(d, [leg])
            if df is not None:
                dfs.append(df)
        if dfs:
            combined = pd.concat(dfs)
            line_chart(combined, "CPU Usage Over Time", y_label="Usage (ratio)", height=320)
        else:
            _no_data_placeholder("CPU usage")

    with tab_cpu2:
        legends2 = ["System", "User", "Nice", "Iowait", "Irq", "Softirq", "Steal", "Idle"]
        exprs2 = [
            'sum(rate(node_cpu_seconds_total{mode="system",instance="$node",job="$job"}[$__rate_interval])) / scalar(count(count(node_cpu_seconds_total{instance="$node",job="$job"}) by (cpu)))',
            'sum(rate(node_cpu_seconds_total{mode="user",instance="$node",job="$job"}[$__rate_interval])) / scalar(count(count(node_cpu_seconds_total{instance="$node",job="$job"}) by (cpu)))',
            'sum(rate(node_cpu_seconds_total{mode="nice",instance="$node",job="$job"}[$__rate_interval])) / scalar(count(count(node_cpu_seconds_total{instance="$node",job="$job"}) by (cpu)))',
            'sum(rate(node_cpu_seconds_total{mode="iowait",instance="$node",job="$job"}[$__rate_interval])) / scalar(count(count(node_cpu_seconds_total{instance="$node",job="$job"}) by (cpu)))',
            'sum(rate(node_cpu_seconds_total{mode="irq",instance="$node",job="$job"}[$__rate_interval])) / scalar(count(count(node_cpu_seconds_total{instance="$node",job="$job"}) by (cpu)))',
            'sum(rate(node_cpu_seconds_total{mode="softirq",instance="$node",job="$job"}[$__rate_interval])) / scalar(count(count(node_cpu_seconds_total{instance="$node",job="$job"}) by (cpu)))',
            'sum(rate(node_cpu_seconds_total{mode="idle",instance="$node",job="$job"}[$__rate_interval])) / scalar(count(count(node_cpu_seconds_total{instance="$node",job="$job"}) by (cpu)))',
        ]
        dfs = []
        for expr, leg in zip(exprs2, legends2[:len(exprs2)]):
            d = query_prometheus(_prep_prom(expr))
            df = prom_to_df(d, [leg])
            if df is not None:
                dfs.append(df)
        if dfs:
            combined = pd.concat(dfs)
            line_chart(combined, "CPU Detailed Usage", y_label="Usage (ratio)", height=320)
        else:
            _no_data_placeholder("CPU detailed")

    # ── Memory ───────────────────────────────────────────────────
    section("Memory")
    tab_m1, tab_m2 = st.tabs(["Overview", "System Load"])

    with tab_m1:
        mem_legends = ["Total", "Used", "Cache + Buffer", "Free", "Swap Used"]
        mem_exprs = [
            'node_memory_MemTotal_bytes{instance="$node",job="$job"}',
            'node_memory_MemTotal_bytes{instance="$node",job="$job"} - node_memory_MemFree_bytes{instance="$node",job="$job"} - (node_memory_Cached_bytes{instance="$node",job="$job"} + node_memory_Buffers_bytes{instance="$node",job="$job"})',
            'node_memory_Cached_bytes{instance="$node",job="$job"} + node_memory_Buffers_bytes{instance="$node",job="$job"}',
            'node_memory_MemFree_bytes{instance="$node",job="$job"}',
            '(node_memory_SwapTotal_bytes{instance="$node",job="$job"} - node_memory_SwapFree_bytes{instance="$node",job="$job"})',
        ]
        dfs = []
        for expr, leg in zip(mem_exprs, mem_legends):
            d = query_prometheus(_prep_prom(expr))
            df = prom_to_df(d, [leg])
            if df is not None:
                dfs.append(df)
        if dfs:
            combined = pd.concat(dfs)
            combined["value"] = combined["value"] / 1e9  # Convert to GB
            line_chart(combined, "Memory Usage (GB)", y_label="GB", height=320)
        else:
            _no_data_placeholder("Memory")

    with tab_m2:
        load_legends = ["Load 1m", "Load 5m", "Load 15m"]
        load_exprs = [
            'node_load1{instance="$node",job="$job"}',
            'node_load5{instance="$node",job="$job"}',
            'node_load15{instance="$node",job="$job"}',
        ]
        dfs = []
        for expr, leg in zip(load_exprs, load_legends):
            d = query_prometheus(_prep_prom(expr))
            df = prom_to_df(d, [leg])
            if df is not None:
                dfs.append(df)
        if dfs:
            combined = pd.concat(dfs)
            line_chart(combined, "System Load Average", y_label="Load", height=320)
        else:
            _no_data_placeholder("System load")

    # ── Network ───────────────────────────────────────────────────
    section("Network Traffic")
    tab_n1, tab_n2 = st.tabs(["Throughput", "Errors & Drops"])

    with tab_n1:
        d_rx = query_prometheus(_prep_prom(
            'rate(node_network_receive_bytes_total{instance="$node",job="$job"}[$__rate_interval])*8'
        ))
        d_tx = query_prometheus(_prep_prom(
            'rate(node_network_transmit_bytes_total{instance="$node",job="$job"}[$__rate_interval])*8'
        ))
        dfs = []
        if d_rx:
            for s in d_rx.get("data", {}).get("result", []):
                dev = s.get("metric", {}).get("device", "unknown")
                df = prom_to_df({"data": {"result": [s]}}, [f"Rx {dev}"])
                if df is not None:
                    dfs.append(df)
        if d_tx:
            for s in d_tx.get("data", {}).get("result", []):
                dev = s.get("metric", {}).get("device", "unknown")
                df = prom_to_df({"data": {"result": [s]}}, [f"Tx {dev}"])
                if df is not None:
                    dfs.append(df)
        if dfs:
            combined = pd.concat(dfs)
            combined["value"] = combined["value"] / 1e6  # bps → Mbps
            line_chart(combined, "Network Traffic (Mbps)", y_label="Mbps", height=320)
        else:
            _no_data_placeholder("Network throughput")

    with tab_n2:
        err_legends = ["Rx Errors", "Tx Errors", "Rx Drops", "Tx Drops"]
        err_exprs = [
            'rate(node_network_receive_errs_total{instance="$node",job="$job"}[$__rate_interval])',
            'rate(node_network_transmit_errs_total{instance="$node",job="$job"}[$__rate_interval])',
            'rate(node_network_receive_drop_total{instance="$node",job="$job"}[$__rate_interval])',
            'rate(node_network_transmit_drop_total{instance="$node",job="$job"}[$__rate_interval])',
        ]
        dfs = []
        for expr, leg in zip(err_exprs, err_legends):
            d = query_prometheus(_prep_prom(expr))
            df = prom_to_df(d, [leg])
            if df is not None:
                dfs.append(df)
        if dfs:
            combined = pd.concat(dfs)
            line_chart(combined, "Network Errors & Drops", y_label="pps", height=320)
        else:
            _no_data_placeholder("Network errors")

    # ── Disk ──────────────────────────────────────────────────────
    section("Disk / Storage")
    tab_d1, tab_d2, tab_d3 = st.tabs(["Space Used", "I/O Throughput", "I/O Operations"])

    with tab_d1:
        d = query_prometheus(_prep_prom(
            '((node_filesystem_size_bytes{instance="$node",job="$job",device!~"rootfs"} - node_filesystem_avail_bytes{instance="$node",job="$job",device!~"rootfs"}) / node_filesystem_size_bytes{instance="$node",job="$job",device!~"rootfs"}) * 100'
        ))
        if d:
            dfs = []
            for s in d.get("data", {}).get("result", []):
                mp = s.get("metric", {}).get("mountpoint", "unknown")
                df = prom_to_df({"data": {"result": [s]}}, [mp])
                if df is not None:
                    dfs.append(df)
            if dfs:
                combined = pd.concat(dfs)
                line_chart(combined, "Filesystem Space Used (%)", y_label="%", height=280)
            else:
                _no_data_placeholder("Disk space")
        else:
            _no_data_placeholder("Disk space")

    with tab_d2:
        d_r = query_prometheus(_prep_prom(
            'rate(node_disk_read_bytes_total{instance="$node",job="$job",device=~"[a-z]+|nvme.*"}[$__rate_interval])'
        ))
        d_w = query_prometheus(_prep_prom(
            'rate(node_disk_written_bytes_total{instance="$node",job="$job",device=~"[a-z]+|nvme.*"}[$__rate_interval])'
        ))
        dfs = []
        for data_src, prefix in [(d_r, "Read"), (d_w, "Write")]:
            if data_src:
                for s in data_src.get("data", {}).get("result", []):
                    dev = s.get("metric", {}).get("device", "?")
                    df = prom_to_df({"data": {"result": [s]}}, [f"{prefix} {dev}"])
                    if df is not None:
                        dfs.append(df)
        if dfs:
            combined = pd.concat(dfs)
            combined["value"] = combined["value"] / 1e6  # B/s → MB/s
            line_chart(combined, "Disk Throughput (MB/s)", y_label="MB/s", height=280)
        else:
            _no_data_placeholder("Disk throughput")

    with tab_d3:
        d_r = query_prometheus(_prep_prom(
            'rate(node_disk_reads_completed_total{instance="$node",job="$job",device=~"[a-z]+|nvme.*"}[$__rate_interval])'
        ))
        d_w = query_prometheus(_prep_prom(
            'rate(node_disk_writes_completed_total{instance="$node",job="$job",device=~"[a-z]+|nvme.*"}[$__rate_interval])'
        ))
        dfs = []
        for data_src, prefix in [(d_r, "Read"), (d_w, "Write")]:
            if data_src:
                for s in data_src.get("data", {}).get("result", []):
                    dev = s.get("metric", {}).get("device", "?")
                    df = prom_to_df({"data": {"result": [s]}}, [f"{prefix} IOps {dev}"])
                    if df is not None:
                        dfs.append(df)
        if dfs:
            combined = pd.concat(dfs)
            line_chart(combined, "Disk I/O Operations", y_label="IOps", height=280)
        else:
            _no_data_placeholder("Disk IOps")

    # ── Temperature ───────────────────────────────────────────────
    section("Hardware Temperature")
    d = query_prometheus(_prep_prom(
        'node_hwmon_temp_celsius{instance="$node",job="$job"}'
    ))
    if d:
        dfs = []
        for s in d.get("data", {}).get("result", []):
            chip = s.get("metric", {}).get("chip", "?")
            sensor = s.get("metric", {}).get("sensor", "?")
            df = prom_to_df({"data": {"result": [s]}}, [f"{chip}/{sensor}"])
            if df is not None:
                dfs.append(df)
        if dfs:
            combined = pd.concat(dfs)
            line_chart(combined, "Hardware Temperature (°C)", y_label="°C", height=280)
        else:
            _no_data_placeholder("Temperature")
    else:
        _no_data_placeholder("Temperature sensors")


# ═══════════════════════════════════════════════════════════════════
#  DASHBOARD 3 — SENSORS READING
# ═══════════════════════════════════════════════════════════════════
def render_sensors():
    st.markdown('<h1 style="color:#89dceb;">IoT Sensors Reading</h1>', unsafe_allow_html=True)
    st.caption(f"Date: **{selected_date}** · Range: **{duration}** · {start_dt.strftime('%H:%M')} → {end_dt.strftime('%H:%M')}")

    # ── Overview ─────────────────────────────────────────────────
    section("Overview — Current Status")

    # Current sintering stage
    q = _prep_loki('''last_over_time(
  {event_type="sensor_data"}
  | json
  | label_format stage="{{.payload_process_parameters_sinteringStage_value}}"
  [5m]
) by (deviceId)''')
    d = query_loki(q)
    if d and d.get("data", {}).get("result"):
        stage_cols = st.columns(len(d["data"]["result"]))
        for i, r in enumerate(d["data"]["result"]):
            dev = r["metric"].get("deviceId", f"Device {i+1}")
            stage = r["metric"].get("stage", "Unknown")
            try:
                if r.get("values"):
                    stage = r["values"][-1][1]
                elif r.get("value"):
                    stage = r["value"][1]
            except Exception:
                pass
            stage_cols[i].metric(f"{dev} — Stage", stage)
    else:
        st.info("No sintering stage data available for this date range")

    # Temperature timeseries
    col_t1, col_t2 = st.columns(2)

    with col_t1:
        temp_legends = ["Zone 1", "Zone 2", "Zone 3"]
        temp_exprs = [
            'max_over_time({event_type="sensor_data"} | json | unwrap payload_process_parameters_temperatureZone1_value [$__interval]) by (deviceId)',
            'max_over_time({event_type="sensor_data"} | json | unwrap payload_process_parameters_temperatureZone2_value [$__interval]) by (deviceId)',
            'max_over_time({event_type="sensor_data"} | json | unwrap payload_process_parameters_temperatureZone3_value [$__interval]) by (deviceId)',
        ]
        dfs = []
        for expr, leg in zip(temp_exprs, temp_legends):
            d = query_loki(_prep_loki(expr))
            df = loki_to_df(d)
            if df is not None:
                df["series"] = df["series"] + f" — {leg}"
                dfs.append(df)
        line_chart(pd.concat(dfs) if dfs else None, "Temperature Zones (°C)", y_label="°C")

    with col_t2:
        ch_legends = ["Chamber", "Setpoint"]
        ch_exprs = [
            'max_over_time({event_type="sensor_data"} | json | unwrap payload_process_parameters_temperatureChamber_value [$__interval]) by (deviceId)',
            'max_over_time({event_type="sensor_data"} | json | unwrap payload_process_parameters_temperatureSetpoint_value [$__interval]) by (deviceId)',
        ]
        dfs = []
        for expr, leg in zip(ch_exprs, ch_legends):
            d = query_loki(_prep_loki(expr))
            df = loki_to_df(d)
            if df is not None:
                df["series"] = df["series"] + f" — {leg}"
                dfs.append(df)
        line_chart(pd.concat(dfs) if dfs else None, "Temperature Chamber & Setpoint (°C)", y_label="°C")

    # ── Pressure & Vacuum ─────────────────────────────────────────
    section("Pressure & Vacuum")
    pv1, pv2 = st.columns(2)

    with pv1:
        pr_legends = ["Chamber", "Forevacuum"]
        pr_exprs = [
            'max_over_time({event_type="sensor_data"} | json | unwrap payload_process_parameters_pressureChamber_value [$__interval]) by (deviceId)',
            'max_over_time({event_type="sensor_data"} | json | unwrap payload_process_parameters_pressureForevacuum_value [$__interval]) by (deviceId)',
        ]
        dfs = []
        for expr, leg in zip(pr_exprs, pr_legends):
            d = query_loki(_prep_loki(expr))
            df = loki_to_df(d)
            if df is not None:
                df["series"] = df["series"] + f" — {leg}"
                dfs.append(df)
        line_chart(pd.concat(dfs) if dfs else None, "Pressure (Pa)", y_label="Pa")

    with pv2:
        d = query_loki(_prep_loki(
            'max_over_time({event_type="sensor_data"} | json | unwrap payload_process_parameters_vacuumPumpSpeed_value [$__interval]) by (deviceId)'
        ))
        df = loki_to_df(d)
        line_chart(df, "Vacuum Pump Speed (RPM)", y_label="RPM")

    # ── Gas Flow & Power ──────────────────────────────────────────
    section("Gas Flow & Heating Power")
    gp1, gp2 = st.columns(2)

    with gp1:
        gas_legends = ["Argon", "Nitrogen", "Hydrogen"]
        gas_exprs = [
            'max_over_time({event_type="sensor_data"} | json | unwrap payload_process_parameters_gasFlowArgon_value [$__interval]) by (deviceId)',
            'max_over_time({event_type="sensor_data"} | json | unwrap payload_process_parameters_gasFlowNitrogen_value [$__interval]) by (deviceId)',
            'max_over_time({event_type="sensor_data"} | json | unwrap payload_process_parameters_gasFlowHydrogen_value [$__interval]) by (deviceId)',
        ]
        dfs = []
        for expr, leg in zip(gas_exprs, gas_legends):
            d = query_loki(_prep_loki(expr))
            df = loki_to_df(d)
            if df is not None:
                df["series"] = df["series"] + f" — {leg}"
                dfs.append(df)
        line_chart(pd.concat(dfs) if dfs else None, "Gas Flow (L/min)", y_label="L/min")

    with gp2:
        d = query_loki(_prep_loki(
            'max_over_time({event_type="sensor_data"} | json | unwrap payload_process_parameters_powerHeatingTotal_value [$__interval]) by (deviceId)'
        ))
        df = loki_to_df(d)
        line_chart(df, "Heating Power Total (kW)", y_label="kW")

    # ── Cycle & Other ─────────────────────────────────────────────
    section("Cycle Time & Environmental Metrics")
    c1, c2 = st.columns(2)

    with c1:
        cy_legends = ["Elapsed", "Remaining"]
        cy_exprs = [
            'max_over_time({event_type="sensor_data"} | json | unwrap payload_process_parameters_cycleTimeElapsed_value [$__interval]) by (deviceId)',
            'max_over_time({event_type="sensor_data"} | json | unwrap payload_process_parameters_cycleTimeRemaining_value [$__interval]) by (deviceId)',
        ]
        dfs = []
        for expr, leg in zip(cy_exprs, cy_legends):
            d = query_loki(_prep_loki(expr))
            df = loki_to_df(d)
            if df is not None:
                df["series"] = df["series"] + f" — {leg}"
                dfs.append(df)
        line_chart(pd.concat(dfs) if dfs else None, "Cycle Time (s)", y_label="Seconds")

    with c2:
        env_legends = ["O₂ Concentration", "Dew Point", "Vibration"]
        env_exprs = [
            'max_over_time({event_type="sensor_data"} | json | unwrap payload_process_parameters_o2Concentration_value [$__interval]) by (deviceId)',
            'max_over_time({event_type="sensor_data"} | json | unwrap payload_process_parameters_dewPoint_value [$__interval]) by (deviceId)',
            'max_over_time({event_type="sensor_data"} | json | unwrap payload_process_parameters_vibrationLevel_value [$__interval]) by (deviceId)',
        ]
        dfs = []
        for expr, leg in zip(env_exprs, env_legends):
            d = query_loki(_prep_loki(expr))
            df = loki_to_df(d)
            if df is not None:
                df["series"] = df["series"] + f" — {leg}"
                dfs.append(df)
        line_chart(pd.concat(dfs) if dfs else None, "O₂ / Dew Point / Vibration")

    # ── Latest Raw Readings Table ─────────────────────────────────
    section("Latest Raw Readings")
    q = _prep_loki(
        '{event_type="sensor_data"} | json '
        '| line_format "{{.deviceId}} | {{.payload_process_parameters_sinteringStage_value}} '
        '| T:{{.payload_process_parameters_temperatureChamber_value}}°C '
        '| Power:{{.payload_process_parameters_powerHeatingTotal_value}}kW '
        '| Elapsed:{{.payload_process_parameters_cycleTimeElapsed_value}}s"'
    )
    d = query_loki(q, limit=300)
    df_raw = loki_logs_to_df(d)
    if df_raw is not None:
        st.dataframe(
            df_raw, use_container_width=True, height=320,
            column_config={"time": st.column_config.DatetimeColumn("Timestamp", format="YYYY-MM-DD HH:mm:ss")}
        )
    else:
        _no_data_placeholder("Latest sensor readings")


# ═══════════════════════════════════════════════════════════════════
#  MAIN ROUTER
# ═══════════════════════════════════════════════════════════════════
if "Gateway" in dashboard:
    render_gateway()
elif "Raspberry" in dashboard:
    render_raspi()
else:
    render_sensors()