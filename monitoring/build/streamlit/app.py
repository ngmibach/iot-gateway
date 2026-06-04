import streamlit as st
import requests
import pandas as pd
from datetime import datetime, timedelta, time
import plotly.express as px

st.set_page_config(page_title="IoT Gateway Monitor", layout="wide")
st.title("IoT Sensor Gateway Monitor")

# Configuration
LOKI_URL = "http://172.17.0.1:3100"
PROMETHUES_URL = "http://172.17.0.1:9090"

# Time Range Selection
time_mode = st.sidebar.radio("Time Selection Mode", ["Quick Range", "Custom Range"], horizontal=True)

if time_mode == "Quick Range":
    TIME_RANGE = st.sidebar.selectbox("Quick Range", ["Last 1h", "Last 6h", "Last 24h", "Last 7d"], index=1)
    custom_start = custom_end = None
else:
    TIME_RANGE = "Custom"
    col_a, col_b = st.sidebar.columns(2)
    with col_a:
        start_date = st.date_input("Start Date", datetime.now().date() - timedelta(days=1))
        start_time = st.time_input("Start Time", time(0, 0))
    with col_b:
        end_date = st.date_input("End Date", datetime.now().date())
        end_time = st.time_input("End Time", time(23, 59))

def get_time_params():
    if time_mode == "Quick Range":
        now = datetime.now()
        if TIME_RANGE == "Last 1h":
            delta = timedelta(hours=1)
            duration_str = "1h"
        elif TIME_RANGE == "Last 6h":
            delta = timedelta(hours=6)
            duration_str = "6h"
        elif TIME_RANGE == "Last 24h":
            delta = timedelta(hours=24)
            duration_str = "24h"
        else:  # 7d
            delta = timedelta(days=7)
            duration_str = "7d"
        
        end_dt = now
        start_dt = now - delta
    else:
        # Custom Range
        start_dt = datetime.combine(start_date, start_time)
        end_dt = datetime.combine(end_date, end_time)
        
        # Calculate approximate duration for Loki queries
        delta = end_dt - start_dt
        if delta.days >= 1:
            duration_str = f"{delta.days + 1}d"
        elif delta.seconds >= 3600:
            duration_str = f"{int(delta.seconds / 3600) + 1}h"
        else:
            duration_str = "1h"
    
    end_ns = int(end_dt.timestamp() * 1e9)
    start_ns = int(start_dt.timestamp() * 1e9)
    return start_ns, end_ns, duration_str

start_ns, end_ns, duration = get_time_params()

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
            timeout=20
        )
        
        if resp.status_code != 200:
            st.error(f"Loki error {resp.status_code}: {resp.text[:600]}")
            return None
        return resp.json()
        
    except Exception as e:
        st.error(f"Query failed: {e}")
        return None


def extract_value(result_item, default=0):
    if not result_item:
        return default
    try:
        if 'value' in result_item and len(result_item.get('value', [])) > 1:
            return float(result_item['value'][1])
        if 'values' in result_item and result_item.get('values'):
            return float(result_item['values'][-1][1])
    except:
        pass
    return default


# ==================== OVERVIEW ====================
st.subheader("Overview")
col1, col2, col3, col4 = st.columns(4)

with col1:
    q = f'sum(count_over_time({{container="iot-nodered", event_type="sensor_data"}}[{duration}]))'
    data = query_loki(q)
    total = int(extract_value(data['data']['result'][0] if data and data.get('data', {}).get('result') else None))
    st.metric("Total Sensor Messages", f"{total:,}")

with col2:
    q = f'sum(rate({{container="iot-nodered", event_type="sensor_data"}}[5m])) * 60'
    data = query_loki(q)
    rate = extract_value(data['data']['result'][0] if data and data.get('data', {}).get('result') else None)
    st.metric("Messages / Minute", f"{rate:.1f}")

with col3:
    q = f'count_over_time({{container="iot-mosquitto"}} |~ "Denied PUBLISH"[{duration}])'
    data = query_loki(q)
    denied = int(extract_value(data['data']['result'][0] if data and data.get('data', {}).get('result') else None))
    st.metric("Denied Publishes", denied)

with col4:
    q = f'sum by (deviceId) (count_over_time({{container="iot-nodered", event_type="sensor_data"}}[{duration}]))'
    data = query_loki(q)
    active = len(data['data']['result']) if data and data.get('data', {}).get('result') else 0
    st.metric("Active Sensors", active)

# ==================== TRANSMISSION ACTIVITY ====================
st.subheader("Transmission Activity")
tab1, tab2 = st.tabs(["Sensor Message Rate", "Messages per Sensor"])

with tab1:
    q = f'rate({{container="iot-nodered", event_type="sensor_data"}}[5m])'
    data = query_loki(q)
    if data and data.get('data', {}).get('result'):
        df_list = []
        for stream in data['data']['result']:
            device = stream['metric'].get('deviceId', 'unknown')
            values = [(int(ts), float(val)) for ts, val in stream.get('values', [])]
            if values:
                temp = pd.DataFrame(values, columns=['timestamp', 'rate'])
                temp['deviceId'] = device
                df_list.append(temp)
        
        if df_list:
            df = pd.concat(df_list)
            df['time'] = pd.to_datetime(df['timestamp'], unit='ns')
            fig = px.line(df, x='time', y='rate', color='deviceId', title="Sensor Message Rate")
            st.plotly_chart(fig, use_container_width=True)

with tab2:
    q = f'sum(count_over_time({{container="iot-nodered", event_type="sensor_data"}}[24h])) by (deviceId)'
    data = query_loki(q)
    if data and data.get('data', {}).get('result'):
        df = pd.DataFrame([
            {
                "deviceId": r['metric'].get('deviceId', 'unknown'), 
                "messages": int(extract_value(r))
            }
            for r in data['data']['result']
        ])
        fig = px.bar(df, x="deviceId", y="messages", title="Messages per Sensor (Last 24h)")
        st.plotly_chart(fig, use_container_width=True)