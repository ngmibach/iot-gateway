import streamlit as st
import pandas as pd
import json
import re
import time
import os
from datetime import datetime

import modules.utils as utils

from ..utils import (
    _prep_loki,
    query_loki,
    query_prometheus_current,
    _extract_scalar,
    loki_to_df,
    loki_logs_to_df,
    line_chart,
    bar_chart,
    _no_data_placeholder,
    section,
    extract_ssl_alert_reason,
)


# ═══════════════════════════════════════════════════════════════════
#  DASHBOARD 1 — GATEWAY ACTIVITIES (Updated to match new Grafana)
# ═══════════════════════════════════════════════════════════════════
def render_gateway():
    st.markdown('<h1 style="color:#89b4fa;">IoT Sensor Gateway — Activities</h1>', unsafe_allow_html=True)
    # st.caption(f"Date: **{selected_date}** · Range: **{duration}** · {start_dt.strftime('%H:%M')} → {end_dt.strftime('%H:%M')}")

    # ── Overview Metrics ──────────────────────────────────────────
    section("Overview")
    c1, c2, c3, c4, c5, c6 = st.columns([1, 1, 1, 1, 1, 1])

    with st.spinner("Loading metrics…"):
        # Total sensor messages
        q = _prep_loki('sum(count_over_time({container="iot-nodered", event_type="sensor_data"}[$__range]))')
        d = query_loki(q)
        total_msgs = int(_extract_scalar(d)) if d else 0

        # Messages/min
        q = _prep_loki('sum(rate({container="iot-nodered", event_type="sensor_data"}[$__range])) * 60')
        d = query_loki(q)
        msgs_min = _extract_scalar(d) if d else 0.0

        # Use the denied-specific time range (computed in app.py based on Range Mode)
        orig_start = utils.start_ns
        orig_end = utils.end_ns
        orig_duration = getattr(utils, 'duration', None)

        # Safely get the denied window (populated on the utils module in app.py)
        denied_start = getattr(utils, 'denied_start_ns', None)
        denied_end   = getattr(utils, 'denied_end_ns', None)
        denied_dur   = getattr(utils, 'denied_duration', None)

        if denied_start is None or denied_end is None:
            # Fallback to the normal sidebar range if the denied values weren't set
            denied_start = start_ns
            denied_end   = end_ns
            denied_dur   = duration

        utils.start_ns = denied_start
        utils.end_ns = denied_end
        utils.duration = denied_dur

        try:
            # Range-aware queries (Full Day → start of day to real now;
            # Custom Hours → the exact selected window)
            q_nodered = _prep_loki('count_over_time({container="iot-nodered", event_type=~"denied_.*"}[$__range])')
            d_nodered = query_loki(q_nodered)
            denied_nodered = int(_extract_scalar(d_nodered)) if d_nodered else 0

            q_hap_count = _prep_loki('count_over_time({container="iot-haproxy"} |~ "mqtts_frontend|handshake|ssl|verify|certificate|c_verify=[1-9]|SC--|C--|reject|NOSRV" [$__range])')
            d_hap = query_loki(q_hap_count)
            denied_hap = int(_extract_scalar(d_hap)) if d_hap else 0

            q_mos_denied = _prep_loki('count_over_time({container="iot-mosquitto"} |~ "Denied PUBLISH" [$__range])')
            d_mos_denied = query_loki(q_mos_denied)
            denied_mos = int(_extract_scalar(d_mos_denied)) if d_mos_denied else 0

            denied = denied_nodered + denied_hap + denied_mos
        finally:
            utils.start_ns = orig_start
            utils.end_ns = orig_end
            if orig_duration is not None:
                utils.duration = orig_duration

        # Live Allowed IPs count from Prometheus (for current/live view)
        live_allowed_ips = 0
        try:
            allowed_d = query_prometheus_current("allowed_ip_count")
            live_allowed_ips = int(_extract_scalar(allowed_d)) if allowed_d else 0
        except Exception:
            pass

    with c1:
        st.metric("Total Sensor Messages", f"{total_msgs:,}")
    with c2:
        st.metric("Messages / Minute", f"{msgs_min:.2f}")
    with c3:
        st.metric("Denied Publishes", f"{denied:,}")
    now = datetime.now()
    is_live_view = (now - end_dt).total_seconds() < 600  # last 10 min = live/current view

    with c4:
        if is_live_view:
            st.metric("Allowed IPs", f"{live_allowed_ips:,}")
        else:
            # historical count from Loki snapshot
            hist_allowed = 0
            try:
                q = '{job="gateway-state", state_type="allowed_ips_acl"} | json'
                d = query_loki(q, limit=3)
                if d and d.get("data", {}).get("result"):
                    for stream in d["data"]["result"]:
                        for ts, line in stream.get("values", []):
                            try:
                                parsed = json.loads(line)
                                if parsed.get("state_type") == "allowed_ips_acl":
                                    ips = parsed.get("allowed_ips") or []
                                    hist_allowed = len(ips)
                                    break
                            except Exception:
                                pass
                        if hist_allowed > 0:
                            break
            except Exception:
                pass
            st.metric("Allowed IPs", f"{hist_allowed:,}", help=f"Historical as of {end_dt.strftime('%Y-%m-%d %H:%M')}")

    # Active Sensors (Table) + Average Transmission Delay
    col_active, col_delay = st.columns([1, 1])

    with col_active:
        st.subheader("Currently Connected Sensors")

        if is_live_view:
            try:
                d = query_prometheus_current("mqtt_connected_sensor")
                rows = []
                if d and d.get("data", {}).get("result"):
                    for r in d["data"]["result"]:
                        m = r.get("metric", {}) or {}
                        dev = m.get("device_id") or m.get("deviceId")
                        if dev:
                            rows.append({
                                "Device ID": dev,
                                "Client ID": m.get("client_id", ""),
                                "Source IP": m.get("source_ip", ""),
                            })
                if rows:
                    # dedup just in case
                    df = pd.DataFrame(rows).drop_duplicates(subset=["Device ID"])
                    st.dataframe(df, use_container_width=True, hide_index=True)
                else:
                    st.info("No currently connected sensors")
            except Exception:
                st.info("No currently connected sensors (state not yet available)")
        else:
            st.caption(f"Historical state as of {end_dt.strftime('%Y-%m-%d %H:%M')} — from gateway state logs shipped by promtail to Loki")
            try:
                q = '{job="gateway-state", state_type="connected_sensors"} | json'
                d = query_loki(q, limit=5)
                state = None
                if d and d.get("data", {}).get("result"):
                    for stream in d["data"]["result"]:
                        for ts, line in stream.get("values", []):
                            try:
                                parsed = json.loads(line)
                                if parsed.get("state_type") == "connected_sensors":
                                    state = parsed
                                    break
                            except Exception:
                                pass
                        if state:
                            break
                if state:
                    details = state.get("details") or {}
                    rows = []
                    for dev, info in details.items():
                        rows.append({
                            "Device ID": dev,
                            "Client ID": info.get("client", ""),
                            "Source IP": info.get("ip", ""),
                        })
                    if rows:
                        df = pd.DataFrame(rows).drop_duplicates(subset=["Device ID"])
                        st.dataframe(df, use_container_width=True, hide_index=True)
                    else:
                        st.info("No connected sensors at the selected time")
                else:
                    st.info("No historical state snapshot found in Loki for the selected time")
            except Exception:
                st.info("Failed to query historical connected sensors state from Loki")

    with col_delay:
        st.subheader("Average Transmission Delay")
        q = _prep_loki('avg_over_time({container="iot-nodered", event_type="sensor_data"} | json | unwrap delay [$__interval]) by (deviceId)')
        d = query_loki(q)
        df_delay = loki_to_df(d)
        if df_delay is not None:
            df_delay["value"] = df_delay["value"] * 1000  # assume ns → ms if needed; adjust based on actual unit
            line_chart(df_delay, "Average Transmission Delay (ms)", y_label="Delay (ms)", height=220)
        else:
            st.info("No delay data")

    # Allowed Source IPs Table
    st.subheader("Allowed Source IPs")

    if is_live_view:
        st.caption("Current state from gateway sync-config (Prometheus textfile)")
        try:
            allowed_table = query_prometheus_current("allowed_ip")
            if allowed_table and allowed_table.get("data", {}).get("result"):
                ips = [r["metric"].get("ip", "unknown") for r in allowed_table["data"]["result"]]
                ip_df = pd.DataFrame({"Allowed IP": sorted(set(ips))})
                st.dataframe(ip_df, use_container_width=True, hide_index=True)
            else:
                st.info("No allowed IPs data")
        except Exception:
            st.info("Failed to load Allowed IPs table")
    else:
        st.caption(f"Historical state as of {end_dt.strftime('%Y-%m-%d %H:%M')} — from gateway state logs shipped by promtail to Loki")
        try:
            q = '{job="gateway-state", state_type="allowed_ips_acl"} | json'
            d = query_loki(q, limit=5)
            state = None
            if d and d.get("data", {}).get("result"):
                for stream in d["data"]["result"]:
                    for ts, line in stream.get("values", []):
                        try:
                            parsed = json.loads(line)
                            if parsed.get("state_type") == "allowed_ips_acl":
                                state = parsed
                                break
                        except Exception:
                            pass
                    if state:
                        break
            if state:
                ips = state.get("allowed_ips") or []
                if ips:
                    ip_df = pd.DataFrame({"Allowed IP": sorted(set(ips))})
                    st.dataframe(ip_df, use_container_width=True, hide_index=True)
                else:
                    st.info("No allowed IPs at the selected time")
            else:
                st.info("No historical state snapshot found in Loki for the selected time")
        except Exception:
            st.info("Failed to query historical allowed IPs state from Loki")

    # Access Control List Table (from Mosquitto ACL, exported via sync-config service to Prometheus textfile)
    st.subheader("Access Control List")

    if is_live_view:
        st.caption("Current ACL state from gateway (Prometheus textfile)")
        try:
            acl_table = query_prometheus_current("acl")
            if acl_table and acl_table.get("data", {}).get("result"):
                # Group by user, separate readwrite vs read topics
                user_topics = {}
                for r in acl_table["data"]["result"]:
                    m = r.get("metric", {})
                    user = m.get("user", "unknown")
                    topic = m.get("topic", "")
                    perm = m.get("permission", "").lower()
                    if user not in user_topics:
                        user_topics[user] = {"readwrite": [], "read": []}
                    if perm == "readwrite":
                        user_topics[user]["readwrite"].append(topic)
                    elif perm == "read":
                        user_topics[user]["read"].append(topic)

                acl_rows = []
                for user in sorted(user_topics.keys()):
                    rw = ", ".join(sorted(user_topics[user]["readwrite"])) if user_topics[user]["readwrite"] else "N/A"
                    r = ", ".join(sorted(user_topics[user]["read"])) if user_topics[user]["read"] else "N/A"
                    acl_rows.append({
                        "User": user,
                        "ReadWrite Permission": rw,
                        "Read Permission": r
                    })
                acl_df = pd.DataFrame(acl_rows)
                st.dataframe(acl_df, use_container_width=True, hide_index=True)
            else:
                st.info("No ACL data")
        except Exception:
            st.info("Failed to load Access Control List table")
    else:
        st.caption(f"Historical state as of {end_dt.strftime('%Y-%m-%d %H:%M')} — from gateway state logs shipped by promtail to Loki")
        try:
            q = '{job="gateway-state", state_type="allowed_ips_acl"} | json'
            d = query_loki(q, limit=5)
            state = None
            if d and d.get("data", {}).get("result"):
                for stream in d["data"]["result"]:
                    for ts, line in stream.get("values", []):
                        try:
                            parsed = json.loads(line)
                            if parsed.get("state_type") == "allowed_ips_acl":
                                state = parsed
                                break
                        except Exception:
                            pass
                    if state:
                        break
            if state:
                acl = state.get("acl") or {}
                acl_rows = []
                for user in sorted(acl.keys()):
                    user_data = acl[user]
                    rw = ", ".join(sorted(user_data.get("readwrite", []))) if user_data.get("readwrite") else "N/A"
                    r = ", ".join(sorted(user_data.get("read", []))) if user_data.get("read") else "N/A"
                    acl_rows.append({
                        "User": user,
                        "ReadWrite Permission": rw,
                        "Read Permission": r
                    })
                if acl_rows:
                    acl_df = pd.DataFrame(acl_rows)
                    st.dataframe(acl_df, use_container_width=True, hide_index=True)
                else:
                    st.info("No ACL at the selected time")
            else:
                st.info("No historical state snapshot found in Loki for the selected time")
        except Exception:
            st.info("Failed to query historical ACL state from Loki")

    # ── Transmission Activity ─────────────────────────────────────
    section("Transmission Activity")
    tab1, tab2 = st.tabs(["Sensor Message Rate", "Messages per Sensor"])

    with tab1:
        q = _prep_loki('rate({container="iot-nodered", event_type="sensor_data"}[$__range])')
        d = query_loki(q)
        df = loki_to_df(d)
        line_chart(df, "Sensor Message Rate (msg/s)", y_label="Rate (msg/s)")

    with tab2:
        # Use 24h for consistency with Grafana (or full selected range)
        q = _prep_loki('sum(count_over_time({container="iot-nodered", event_type="sensor_data"}[24h])) by (deviceId)')
        d = query_loki(q)
        if d and d.get("data", {}).get("result"):
            agg = pd.DataFrame([
                {"series": r["metric"].get("deviceId", "unknown"),
                 "value": int(_extract_scalar({"data": {"result": [r]}}))}
                for r in d["data"]["result"]
            ])
            bar_chart(agg, "Messages per Sensor (24h)", y_label="Message Count")
        else:
            _no_data_placeholder("Messages per Sensor")

    # ── Latest Readings & Logs ────────────────────────────────────
    section("Latest Readings & Logs")

    # Latest Sensor Readings (full width - large table, needs more horizontal space)
    st.markdown('<span style="font-weight:700;color:#89b4fa;">Latest Sensor Activities Reading</span>', unsafe_allow_html=True)
    q = _prep_loki('{container="iot-nodered", event_type="sensor_data"}')
    d = query_loki(q, limit=300)

    if d and d.get("data", {}).get("result"):
        rows = []
        for stream in d["data"]["result"]:
            for ts, line in stream.get("values", []):
                try:
                    parsed = json.loads(line) if isinstance(line, str) else line
                    row = {
                        "time": pd.Timestamp(datetime.fromtimestamp(int(ts) / 1e9)),
                        "deviceId": parsed.get("deviceId"),
                        "topic": parsed.get("topic"),
                        "source_ip": parsed.get("source_ip"),
                        "delay": parsed.get("delay"),
                        "Payload Size (bytes)": parsed.get("payload_size_bytes"),
                        # Add more fields as needed
                    }
                    rows.append(row)
                except Exception:
                    rows.append({"time": pd.Timestamp(datetime.fromtimestamp(int(ts) / 1e9)), "log": line})
        df_logs = pd.DataFrame(rows)
        if not df_logs.empty:
            df_logs = df_logs.sort_values("time", ascending=False)
            st.dataframe(df_logs, use_container_width=True, height=380)
        else:
            _no_data_placeholder("Sensor readings")
    else:
        _no_data_placeholder("Sensor readings")

    # Recent Denied Events table 
    st.markdown('<span style="font-weight:700;color:#f38ba8;">Recent Denied Events</span>', unsafe_allow_html=True)

    rows = []

    # 1. Structured denied events from Node-RED (Mosquitto layer)
    q = _prep_loki('{container="iot-nodered", event_type=~"denied_.*"}')
    d = query_loki(q, limit=100)
    if d and d.get("data", {}).get("result"):
        for stream in d["data"]["result"]:
            for ts, line in stream.get("values", []):
                try:
                    parsed = json.loads(line) if isinstance(line, str) else line
                    rows.append({
                        "time": pd.Timestamp(datetime.fromtimestamp(int(ts) / 1e9)),
                        "source_ip": parsed.get("source_ip"),
                        "denied_type": parsed.get("denied_type"),
                        "reason": parsed.get("reason"),
                    })
                except Exception:
                    pass

    # 2. HAProxy layer denials (SSL handshake failure for no/bad certs, IP ACL rejects)
    q_hap = _prep_loki('{container="iot-haproxy"} |~ "SSL handshake failure|handshake failure|c_verify=|SC--|C--|reject|NOSRV|alert"')
    d_hap = query_loki(q_hap, limit=150)

    if d_hap and d_hap.get("data", {}).get("result"):
        ip_re = re.compile(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b')

        for stream in d_hap["data"]["result"]:
            metric = stream.get("metric") or stream.get("stream") or {}
            label_src = metric.get("src_ip")
            label_cver = metric.get("c_verify")
            label_term = metric.get("term_state")

            for ts, line in stream.get("values", []):
                try:
                    line_str = line if isinstance(line, str) else str(line)
                    
                    # Default values
                    dtype = "ha_proxy_failure"
                    reason = None

                    # === SSL Handshake Failure Handling ===
                    if "SSL handshake failure" in line_str:
                        detail = extract_ssl_alert_reason(line_str)
                        reason = f"{detail}"

                        # Add c_verify info if available
                        cver = label_cver or ""
                        if "c_verify=" in line_str:
                            cver_match = re.search(r'c_verify=(\d+)', line_str)
                            if cver_match:
                                cver = cver_match.group(1)

                        if cver and cver.strip() not in ("", "0"):
                            reason = f"SSL handshake failure (c_verify={cver}) - {detail}"

                    # === IP ACL or Early Reject Handling ===
                    term = (label_term or "").upper()
                    if term and ("C--" in term or term.startswith("SC") or "C---" in term):
                        dtype = "ip_acl_reject"
                        reason = "IP ACL reject or early client close at HAProxy"
                    elif "<NOSRV>" in line_str or "NOSRV" in line_str:
                        dtype = "ip_acl_reject"
                        reason = "No backend server (frontend reject before proxy to mosquitto)"

                    # Add to rows only if we found a valid denial reason
                    if reason:
                        src_ip = label_src or (ip_re.search(line_str).group(1) if ip_re.search(line_str) else "unknown")
                        rows.append({
                            "time": pd.Timestamp(datetime.fromtimestamp(int(ts) / 1e9)),
                            "source_ip": src_ip,
                            "denied_type": dtype,
                            "reason": reason,
                        })

                except Exception:
                    pass

    # 3. Mosquitto ACL publish denials
    client_ip_map = {}
    q_conn = _prep_loki('{container="iot-mosquitto"} |~ "New client connected from"')
    d_conn = query_loki(q_conn, limit=200)
    if d_conn and d_conn.get("data", {}).get("result"):
        conn_re = re.compile(r"New client connected from ([\d.]+):\d+ as ([^\s(]+)")
        for stream in d_conn["data"]["result"]:
            for ts, line in stream.get("values", []):
                try:
                    line_str = line if isinstance(line, str) else str(line)
                    match = conn_re.search(line_str)
                    if match:
                        ip = match.group(1)
                        cid = match.group(2)
                        client_ip_map[cid] = ip
                except Exception:
                    pass

    q_mos = _prep_loki('{container="iot-mosquitto"} |~ "Denied PUBLISH"')
    d_mos = query_loki(q_mos, limit=50)
    if d_mos and d_mos.get("data", {}).get("result"):
        mos_re = re.compile(r"Denied PUBLISH from ([^\s(]+).*'([^']+)'.*\((\d+) bytes\)")
        for stream in d_mos["data"]["result"]:
            for ts, line in stream.get("values", []):
                try:
                    line_str = line if isinstance(line, str) else str(line)
                    match = mos_re.search(line_str)
                    if match:
                        clientId = match.group(1)
                        topic = match.group(2)
                        size = match.group(3)
                        src_ip = client_ip_map.get(clientId, f"mosquitto log (client {clientId})")
                        rows.append({
                            "time": pd.Timestamp(datetime.fromtimestamp(int(ts) / 1e9)),
                            "source_ip": src_ip,
                            "denied_type": "acl_publish",
                            "reason": f"denied publish to incorrect topic",
                        })
                    elif "Denied PUBLISH" in line_str:
                        rows.append({
                            "time": pd.Timestamp(datetime.fromtimestamp(int(ts) / 1e9)),
                            "source_ip": "mosquitto log",
                            "denied_type": "acl_publish",
                            "reason": "denied publish to incorrect topic",
                        })
                except Exception:
                    pass

    if rows:
        df_denied = pd.DataFrame(rows).sort_values("time", ascending=False)
        st.dataframe(df_denied, use_container_width=True, height=220)
    else:
        st.info("No denied events recorded")

    # Recent MQTT Events (full width below - large table, needs more horizontal space)
    st.markdown('<span style="font-weight:700;color:#89dceb;">Recent MQTT Events</span>', unsafe_allow_html=True)
    # Enhanced pattern to surface HAProxy denials (now that logs contain c_verify, term states, frontend name, and our custom format).
    q = _prep_loki('{container=~"iot-mosquitto|iot-haproxy"} |~ "New client|PUBLISH|Denied|DISCONNECT|not authorised|SSL|verify|reject|error|c_verify|mqtts_frontend|SC--|C--"')
    d = query_loki(q, limit=200)
    df_mqtt = loki_logs_to_df(d)
    if df_mqtt is not None:
        st.dataframe(df_mqtt, use_container_width=True, height=380,
                     column_config={"time": st.column_config.DatetimeColumn("Time", format="HH:mm:ss")})
    else:
        _no_data_placeholder("MQTT events")
