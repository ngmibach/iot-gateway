import streamlit as st
import requests
import pandas as pd
from datetime import datetime, timedelta
import plotly.express as px
import plotly.graph_objects as go

st.set_page_config(page_title="IoT Gateway Monitor", layout="wide")
st.title("IoT Sensor Gateway Monitor")

# Configuration
LOKI_URL = "http://loki:3100"
TIME_RANGE = st.sidebar.selectbox("Time Range", ["Last 1h", "Last 6h", "Last 24h", "Last 7d"], index=1)

def get_time_params():
    if TIME_RANGE == "Last 1h":
        delta = timedelta(hours=1)
    elif TIME_RANGE == "Last 6h":
        delta = timedelta(hours=6)
    elif TIME_RANGE == "Last 24h":
        delta = timedelta(hours=24)
    else:
        delta = timedelta(days=7)
    
    end = int(datetime.now().timestamp() * 1e9)
    start = int((datetime.now() - delta).timestamp() * 1e9)
    return start, end

start_ns, end_ns = get_time_params()

def query_loki(query, limit=1000):
    try:
        resp = requests.get(
            f"{LOKI_URL}/loki/api/v1/query_range",
            params={
                "query": query,
                "start": start_ns,
                "end": end_ns,
                "limit": limit,
                "direction": "backward"
            },
            timeout=15
        )
        
        if resp.status_code != 200:
            st.error(f"Loki error {resp.status_code}: {resp.text[:500]}")
            return None
            
        return resp.json()
        
    except Exception as e:
        st.error(f"Loki query failed: {e}")
        return None

# ==================== OVERVIEW METRICS ====================
st.subheader("Overview")

col1, col2, col3, col4 = st.columns(4)

with col1:
    total_msgs = query_loki('sum(count_over_time({container="iot-nodered", event_type="sensor_data"}[$__range]))')
    total_count = int(total_msgs['data']['result'][0]['value'][1]) if total_msgs and total_msgs['data']['result'] else 0
    st.metric("Total Sensor Messages", f"{total_count:,}")

with col2:
    msgs_per_min = query_loki('sum(rate({container="iot-nodered", event_type="sensor_data"}[5m])) * 60')
    rate = float(msgs_per_min['data']['result'][0]['value'][1]) if msgs_per_min and msgs_per_min['data']['result'] else 0
    st.metric("Messages / Minute", f"{rate:.1f}")

with col3:
    denied = query_loki('count_over_time({container="iot-mosquitto"} |~ "Denied PUBLISH"[$__range])')
    denied_count = int(denied['data']['result'][0]['value'][1]) if denied and denied['data']['result'] else 0
    st.metric("Denied Publishes", denied_count, delta=None, delta_color="inverse")

with col4:
    active_sensors = query_loki('sum by (deviceId) (count_over_time({container="iot-nodered", event_type="sensor_data"}[$__range]))')
    active_count = len(active_sensors['data']['result']) if active_sensors and active_sensors['data']['result'] else 0
    st.metric("Active Sensors", active_count)

# ==================== TRANSMISSION ACTIVITY ====================
st.subheader("Transmission Activity")

tab1, tab2 = st.tabs(["Sensor Message Rate", "Messages per Sensor"])

with tab1:
    rate_data = query_loki('rate({container="iot-nodered", event_type="sensor_data"}[5m])')
    if rate_data and rate_data['data']['result']:
        df_list = []
        for stream in rate_data['data']['result']:
            device = stream['metric'].get('deviceId', 'unknown')
            values = [(int(ts), float(val)) for ts, val in stream['values']]
            temp_df = pd.DataFrame(values, columns=['timestamp', 'rate'])
            temp_df['deviceId'] = device
            df_list.append(temp_df)
        
        if df_list:
            df = pd.concat(df_list)
            df['time'] = pd.to_datetime(df['timestamp'], unit='ns')
            fig = px.line(df, x='time', y='rate', color='deviceId', title="Sensor Message Rate")
            st.plotly_chart(fig, use_container_width=True)

with tab2:
    bar_data = query_loki('sum(count_over_time({container="iot-nodered", event_type="sensor_data"}[24h])) by (deviceId)')
    if bar_data and bar_data['data']['result']:
        data = []
        for r in bar_data['data']['result']:
            data.append({
                "deviceId": r['metric'].get('deviceId', 'unknown'),
                "messages": int(r['value'][1])
            })
        df_bar = pd.DataFrame(data)
        fig = px.bar(df_bar, x="deviceId", y="messages", title="Messages per Sensor (24h)")
        st.plotly_chart(fig, use_container_width=True)

# ==================== LATEST READINGS ====================
st.subheader("Latest Sensor Readings")

readings = query_loki('{container="iot-nodered", event_type="sensor_data"}', limit=50)

if readings and readings['data']['result']:
    rows = []
    for stream in readings['data']['result']:
        for ts, line in stream['values']:
            try:
                import json
                payload = json.loads(line)
                rows.append({
                    "Time": pd.to_datetime(int(ts), unit='ns'),
                    "Device": payload.get('deviceId'),
                    "Topic": payload.get('topic'),
                    "Value": payload.get('payload', {}).get('value'),
                    "Unit": payload.get('payload', {}).get('unit'),
                    "Battery": payload.get('payload', {}).get('battery')
                })
            except:
                continue
    
    if rows:
        df_readings = pd.DataFrame(rows)
        st.dataframe(df_readings.sort_values("Time", ascending=False), use_container_width=True, hide_index=True)

# ==================== RECENT MQTT EVENTS ====================
st.subheader("Recent MQTT Events")

mqtt_logs = query_loki('{container="iot-mosquitto"} |~ "New client|PUBLISH|Denied|DISCONNECT"', limit=100)

if mqtt_logs and mqtt_logs['data']['result']:
    logs_list = []
    for stream in mqtt_logs['data']['result']:
        for ts, line in stream['values']:
            logs_list.append({
                "Time": pd.to_datetime(int(ts), unit='ns'),
                "Message": line
            })
    
    if logs_list:
        df_logs = pd.DataFrame(logs_list).sort_values("Time", ascending=False)
        st.dataframe(df_logs, use_container_width=True, hide_index=True)