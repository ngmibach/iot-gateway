import streamlit as st
from datetime import datetime, time as dtime
from streamlit_autorefresh import st_autorefresh

import modules.utils as u
import modules.dashboards.gateway as gateway_mod
import modules.dashboards.raspi as raspi_mod
import modules.dashboards.sensors as sensors_mod
import modules.dashboards.control_plane as control_plane_mod
from modules.dashboards.gateway import *
from modules.dashboards.raspi import *
from modules.dashboards.sensors import *
from modules.dashboards.control_plane import *

st.set_page_config(
    page_title="IoT Gateway Monitor",
    layout="wide",
    initial_sidebar_state="expanded"
)

st.markdown("""
<style>
    div[data-testid="stRadio"] label { font-size: 14px; }
    div[data-testid="metric-container"] {
        background-color: #1e1e2e;
        border: 1px solid #313244;
        border-radius: 8px;
        padding: 12px;
    }
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

# Gitea Control Plane (used to dispatch workflows via the seeded admin/actions repo)
GITEA_URL = "http://172.17.0.1:5000"
GITEA_OWNER = "admin"
GITEA_REPO = "actions"
GITEA_USER = "admin"
GITEA_PASS = "admin"

# ───────────────────────── Sidebar ───────────────────────────────
with st.sidebar:
    st.markdown('<p class="sidebar-heading" style="color:#89dceb; font-size:1.1rem;">IoT Gateway Monitor</p>', unsafe_allow_html=True)
    st.markdown("---")

    # ── Refresh Control ──
    st.markdown('<p class="sidebar-heading" style="color:#a6e3a1;">Live Update Settings</p>', unsafe_allow_html=True)
    
    auto_refresh = st.toggle("Enable Live Updates", value=True)
    
    if auto_refresh:
        refresh_options = {
            "5 seconds": 5,
            "10 seconds": 10,
            "15 seconds": 15,
            "30 seconds": 30,
            "1 minute": 60,
            "5 minutes": 300
        }
        refresh_label = st.selectbox("Update Interval", options=list(refresh_options.keys()), index=2)
        refresh_seconds = refresh_options[refresh_label]
    else:
        refresh_seconds = 0

    st.markdown("---")

    # Date & Time Range (rest of sidebar remains same)
    st.markdown('<p class="sidebar-heading" style="color:#b4befe;">Date & Time Range</p>', unsafe_allow_html=True)
    selected_date = st.date_input("Date", value=datetime.now().date())

    time_mode = st.radio("Range Mode", ["Full Day", "Custom Hours"], horizontal=True)
    if time_mode == "Full Day":
        start_dt = datetime.combine(selected_date, dtime(0, 0, 0))
        end_dt = datetime.combine(selected_date, dtime(23, 59, 59))
    else:
        c1, c2 = st.columns(2)
        with c1: sh = st.time_input("From", value=dtime(0, 0))
        with c2: eh = st.time_input("To", value=dtime(23, 59))
        start_dt = datetime.combine(selected_date, sh)
        end_dt = datetime.combine(selected_date, eh)

    st.caption(f"▶ {start_dt.strftime('%Y-%m-%d %H:%M')}")
    st.caption(f"◀ {end_dt.strftime('%Y-%m-%d %H:%M')}")

    st.markdown("---")
    st.markdown('<p class="sidebar-heading" style="color:#a6adc8;">Prometheus Target (node-exporter)</p>', unsafe_allow_html=True)
    node_instance = st.text_input("Instance", "raspberry-pi-gateway")
    job_name = st.text_input("Job", "node")

    st.markdown("---")
    st.caption("Loki: " + LOKI_URL)
    st.caption("Prometheus: " + PROMETHEUS_URL)

# ───────────────────────── Time range calculations ─────────────────────────
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

prom_step = max(60, int(delta.total_seconds() / 300))
prom_step_str = f"{prom_step}s"

# ── Denied Publishes time window (special logic) ──
if time_mode == "Full Day":
    # From start of the selected day to real "now"
    denied_start_dt = datetime.combine(selected_date, dtime(0, 0, 0))
    denied_end_dt = datetime.now()
else:
    # Use the exact custom hours selected by the user
    denied_start_dt = start_dt
    denied_end_dt = end_dt

denied_delta = denied_end_dt - denied_start_dt
denied_total_hours = max(1, int(denied_delta.total_seconds() / 3600) + 1)
if denied_delta.days >= 1:
    denied_duration = f"{denied_delta.days + 1}d"
elif denied_total_hours >= 1:
    denied_duration = f"{denied_total_hours}h"
else:
    denied_duration = "1h"

# Expose on both the gateway module (for any direct access) and the shared utils module
# (the render functions read from utils via getattr)
gateway_mod.denied_start_ns = int(denied_start_dt.timestamp() * 1e9)
gateway_mod.denied_end_ns   = int(denied_end_dt.timestamp() * 1e9)
gateway_mod.denied_duration = denied_duration

u.denied_start_ns = int(denied_start_dt.timestamp() * 1e9)
u.denied_end_ns   = int(denied_end_dt.timestamp() * 1e9)
u.denied_duration = denied_duration

# ───────────────────────── Populate module context (for dashboards/utils) ─────────────────────────
u.LOKI_URL = LOKI_URL
u.PROMETHEUS_URL = PROMETHEUS_URL
u.start_ns = start_ns
u.end_ns = end_ns
u.start_s = start_s
u.end_s = end_s
u.duration = duration
u.prom_step_str = prom_step_str
u.start_dt = start_dt
u.end_dt = end_dt
u.selected_date = selected_date
u.node_instance = node_instance
u.job_name = job_name

# Gitea (Control Plane)
u.GITEA_URL = GITEA_URL
u.GITEA_OWNER = GITEA_OWNER
u.GITEA_REPO = GITEA_REPO
u.GITEA_USER = GITEA_USER
u.GITEA_PASS = GITEA_PASS

gateway_mod.start_dt = start_dt
gateway_mod.end_dt = end_dt
gateway_mod.duration = duration
gateway_mod.selected_date = selected_date

raspi_mod.start_dt = start_dt
raspi_mod.end_dt = end_dt
raspi_mod.duration = duration
raspi_mod.selected_date = selected_date
raspi_mod.node_instance = node_instance
raspi_mod.job_name = job_name

sensors_mod.start_dt = start_dt
sensors_mod.end_dt = end_dt
sensors_mod.duration = duration
sensors_mod.selected_date = selected_date

# Control Plane does not use date range but we still bind Gitea config for safety
control_plane_mod.GITEA_URL = u.GITEA_URL
control_plane_mod.GITEA_OWNER = u.GITEA_OWNER
control_plane_mod.GITEA_REPO = u.GITEA_REPO
control_plane_mod.GITEA_USER = u.GITEA_USER
control_plane_mod.GITEA_PASS = u.GITEA_PASS

# Bind live refresh state so Control Plane can show a nice "paused" message
control_plane_mod.auto_refresh = auto_refresh
control_plane_mod.refresh_seconds = refresh_seconds


# ═══════════════════════════════════════════════════════════════════
#  MAIN TABS
# ═══════════════════════════════════════════════════════════════════
tab_gateway, tab_raspi, tab_sensors, tab_control = st.tabs([
    "Gateway Activities",
    "Gateway Metrics",
    "Sensors Reading",
    "Control Plane",
])

with tab_gateway:
    st.session_state["active_tab"] = "Gateway Activities"
    if auto_refresh and refresh_seconds > 0:
        st_autorefresh(interval=refresh_seconds * 1000, limit=None, key="datarefresh-gateway-activities")
    render_gateway()

with tab_raspi:
    st.session_state["active_tab"] = "raspi"
    if auto_refresh and refresh_seconds > 0:
        st_autorefresh(interval=refresh_seconds * 1000, limit=None, key="datarefresh-gateway-metrics")
    render_raspi()

with tab_sensors:
    st.session_state["active_tab"] = "sensors"
    if auto_refresh and refresh_seconds > 0:
        st_autorefresh(interval=refresh_seconds * 1000, limit=None, key="datarefresh-sensors")
    render_sensors()

with tab_control:
    st.session_state["active_tab"] = "Control Plane"
    # Large fixed interval for Control Plane to avoid unnecessary load
    if auto_refresh:
        st_autorefresh(interval=30 * 60 * 1000, limit=None, key="datarefresh-control-plane")  # 30 minutes
    render_control_plane()

st.sidebar.caption(f"🕒 Last updated: {datetime.now().strftime('%H:%M:%S')}")