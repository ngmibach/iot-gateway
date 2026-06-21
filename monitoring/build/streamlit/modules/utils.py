import streamlit as st
import requests
import pandas as pd
from datetime import datetime, timedelta, time as dtime
import plotly.express as px
import plotly.graph_objects as go
import re

# ═══════════════════════════════════════════════════════════════════
#  RUNTIME CONTEXT
# ═══════════════════════════════════════════════════════════════════
LOKI_URL = "http://172.17.0.1:3100"
PROMETHEUS_URL = "http://172.17.0.1:9090"

GITEA_URL = "http://172.17.0.1:5000"
GITEA_OWNER = "admin"
GITEA_REPO = "actions"
GITEA_USER = "admin"
GITEA_PASS = "admin"

start_ns = 0
end_ns = 0
start_s = 0
end_s = 0
duration = "1h"
prom_step_str = "60s"

start_dt = None
end_dt = None
selected_date = None
node_instance = "172.17.0.1:9100"
job_name = "node"

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

def query_loki_latest(query: str, limit: int = 1000):
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

@st.cache_data(ttl=10, show_spinner=False)
def query_prometheus_instant(query: str, at_time: int | None = None):
    try:
        params = {"query": query}
        t = at_time if at_time is not None else end_s
        params["time"] = t
        r = requests.get(
            f"{PROMETHEUS_URL}/api/v1/query",
            params=params,
            timeout=20,
        )
        if r.status_code != 200:
            return None
        return r.json()
    except Exception:
        return None


@st.cache_data(ttl=2, show_spinner=False)
def query_prometheus_latest(query: str):
    try:
        r = requests.get(
            f"{PROMETHEUS_URL}/api/v1/query",
            params={"query": query},
            timeout=20,
        )
        if r.status_code != 200:
            return None
        return r.json()
    except Exception:
        return None


def query_prometheus_current(query: str):
    """Always fetch the absolute latest value from Prometheus with **no caching at all**.

    Use this for "current stage of the docker services" views (Active Containers,
    current per-container CPU/Mem bars, services usage table, etc.) so that
    stopping/starting containers is reflected on the very next autorefresh tick
    (e.g. 5s) with zero cache staleness.
    """
    try:
        r = requests.get(
            f"{PROMETHEUS_URL}/api/v1/query",
            params={"query": query},
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

    span_hours = (end_dt - start_dt).total_seconds() / 3600
    if span_hours <= 1:
        tick_fmt = "%H:%M:%S"
    elif span_hours <= 24:
        tick_fmt = "%H:%M"
    else:
        tick_fmt = "%m-%d %H:%M"

    n_series = df["series"].nunique()
    legend_rows = max(1, -(-n_series // 4))
    bottom_margin = 20 + legend_rows * 26

    fig = px.line(df, x="time", y="value", color="series",
                  title=title, labels={"value": y_label, "time": ""})
    fig.update_layout(
        height=height + bottom_margin,
        margin=dict(l=10, r=10, t=50, b=bottom_margin),
        title=dict(
            text=title,
            x=0.5,
            xanchor="center",
            yanchor="top",
            font=dict(size=14),
            pad=dict(b=8),
        ),
        legend=dict(
            orientation="h",
            yanchor="top",
            y=-0.02,
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
        range=[start_dt, end_dt],
        tickformat=tick_fmt,
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


def horizontal_bar_chart(df: pd.DataFrame | None, title: str, y_label: str = "Value",
                         height: int = 280):
    """Horizontal bars, ideal for per-item breakdowns like CPU % per container (bargauge style)."""
    if df is None or df.empty:
        _no_data_placeholder(title)
        return
    fig = px.bar(df, x="value", y="series", orientation="h", title=title,
                 labels={"value": y_label, "series": ""})
    fig.update_layout(height=height, margin=dict(l=10, r=10, t=40, b=10),
                      plot_bgcolor="#1e1e2e", paper_bgcolor="#1e1e2e",
                      font_color="#cdd6f4", showlegend=False)
    fig.update_xaxes(gridcolor="#313244")
    fig.update_yaxes(gridcolor="#313244", autorange="reversed")
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
#  Gitea Actions / Control Plane helpers
# ═══════════════════════════════════════════════════════════════════
def gitea_dispatch_workflow(workflow_file: str, inputs: dict | None = None, ref: str = "main") -> dict:
    """Dispatch a workflow_run using Gitea's workflow_dispatch API.
    Returns a dict with success flag and details.
    """
    base = (GITEA_URL or "http://172.17.0.1:5000").rstrip("/")
    url = f"{base}/api/v1/repos/{GITEA_OWNER}/{GITEA_REPO}/actions/workflows/{workflow_file}/dispatches"

    payload = {"ref": ref}
    if inputs:
        clean_inputs = {k: v for k, v in inputs.items() if v not in (None, "")}
        if clean_inputs:
            payload["inputs"] = clean_inputs

    try:
        resp = requests.post(
            url,
            json=payload,
            auth=(GITEA_USER, GITEA_PASS),
            timeout=20,
            headers={"Accept": "application/json", "Content-Type": "application/json"},
        )
        if resp.status_code in (200, 201, 204):
            return {"success": True, "status_code": resp.status_code}
        else:
            return {
                "success": False,
                "status_code": resp.status_code,
                "error": (resp.text or resp.reason)[:600],
            }
    except Exception as ex:
        return {"success": False, "error": str(ex)}
    
def extract_ssl_alert_reason(log_line: str) -> str:
    """Extract only the human-readable alert part like'"""
    match = re.search(r'tlsv1 alert (.+?)(?:\)|$)', log_line)
    if match:
        return match.group(1).strip()
    
    match = re.search(r'::\s*(.+?)(?:\)|$)', log_line)
    if match:
        return match.group(1).strip()
    
    return "unknown error"