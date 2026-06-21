import streamlit as st
import pandas as pd

from ..utils import (
    _prep_loki,
    query_loki,
    loki_to_df,
    loki_logs_to_df,
    line_chart,
    _no_data_placeholder,
    section,
)

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
