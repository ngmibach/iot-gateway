import streamlit as st
import pandas as pd

from ..utils import (
    _prep_prom,
    query_prometheus_instant,
    query_prometheus,
    query_prometheus_latest,
    query_prometheus_current,
    prom_to_df,
    line_chart,
    gauge_chart,
    horizontal_bar_chart,
    _no_data_placeholder,
    section,
    _extract_scalar,
    PROMETHEUS_URL,
)

# ═══════════════════════════════════════════════════════════════════
#  DASHBOARD 2 — GATEWAY METRICS (node-exporter + cadvisor)
# ═══════════════════════════════════════════════════════════════════
def render_raspi():
    st.markdown('<h1 style="color:#f38ba8;">Gateway — Raspberry Pi Metrics</h1>', unsafe_allow_html=True)
    st.caption(f"Instance: **{node_instance}** · Job: **{job_name}** · Date: **{selected_date}** · {start_dt.strftime('%H:%M')} → {end_dt.strftime('%H:%M')}")

    def prom_scalar(expr: str) -> float:
        """Latest scalar. Tries the (prepped) expr; returns 0 on empty."""
        d = query_prometheus_latest(_prep_prom(expr))
        return _extract_scalar(d)

    def prom_latest_rows(expr: str):
        """Return list of (metric_dict, value) for multi-result latest queries (e.g. disk devices)."""
        d = query_prometheus_latest(_prep_prom(expr))
        if not d:
            return []
        out = []
        for r in d.get("data", {}).get("result", []):
            m = r.get("metric", {}) or {}
            v = 0.0
            try:
                if "value" in r:
                    v = float(r["value"][1])
                elif "values" in r and r["values"]:
                    v = float(r["values"][-1][1])
            except Exception:
                v = 0.0
            out.append((m, v))
        return out

    def _try_latest_scalar(candidates, prefer_positive=True):
        last_resort = None
        for expr in candidates:
            v = prom_scalar(expr)
            d = query_prometheus_latest(_prep_prom(expr))
            has_result = bool(d and d.get("data", {}).get("result"))
            if v and v > 0:
                return v, expr
            if has_result:
                if not prefer_positive:
                    return v, expr
                # remember first real result (may be 0) as last resort
                if last_resort is None:
                    last_resort = (v, expr)
        if last_resort:
            return last_resort
        if candidates:
            return prom_scalar(candidates[0]), candidates[0]
        return 0.0, ""

    def _pick_rootfs_bytes(kind: str):
        base = "node_filesystem_avail_bytes" if kind == "avail" else "node_filesystem_size_bytes"
        cands = [
            f'{base}{{instance="$node",job="$job",mountpoint="/",fstype!="rootfs"}}',
            f'{base}{{instance="$node",job="$job",mountpoint="/"}}',
            f'{base}{{instance="$node",job="$job",device="/dev/root"}}',
            f'{base}{{mountpoint="/",device="/dev/root"}}',
            f'{base}{{mountpoint="/"}}',
            base,  # bare like the reference JSON
        ]
        for c in cands:
            d = query_prometheus_latest(_prep_prom(c))
            if not d:
                continue
            results = d.get("data", {}).get("result", [])
            if not results:
                continue
            # Score results: prefer mountpoint=/ and (device has root or mmc or ext4 fstype)
            best = None
            best_score = -1
            for r in results:
                m = r.get("metric", {}) or {}
                mp = (m.get("mountpoint") or "").strip()
                dev = (m.get("device") or "").lower()
                fst = (m.get("fstype") or "").lower()
                val = _extract_scalar({"data": {"result": [r]}})
                score = 0
                if mp == "/":
                    score += 10
                if "root" in dev or "mmcblk" in dev:
                    score += 5
                if fst == "ext4":
                    score += 3
                if "tmpfs" in fst or "overlay" in fst or dev.startswith("shm"):
                    score -= 20
                if score > best_score:
                    best_score = score
                    best = r
            if best is not None:
                return _extract_scalar({"data": {"result": [best]}})
            # fallback to first result if nothing scored
            return _extract_scalar(d)
        return 0.0

    def _get_disk_io_now():
        exprs = [
            'node_disk_io_now{instance="$node",job="$job",device=~"mmcblk0|mmcblk0p1|mmcblk0p2"}',
            'node_disk_io_now{device=~"mmcblk0|mmcblk0p1|mmcblk0p2"}',
            'node_disk_io_now{instance="$node",job="$job",device=~"mmcblk.*|sd.*"}',
            'node_disk_io_now{device=~"mmcblk.*|sd.*|nvme.*"}',
        ]
        for ex in exprs:
            rows = prom_latest_rows(ex)
            if rows:
                # sort so main disk first
                rows.sort(key=lambda mv: (0 if mv[0].get("device") in ("mmcblk0", "mmcblk0p2") else 1, mv[0].get("device", "")))
                return rows
        return []

    # ── General Status (modeled directly on Raspi-monitoring.json panels) ──
    section("General Status")

    # Temperature
    temp, _ = _try_latest_scalar([
        "node_thermal_zone_temp",
        'node_hwmon_temp_celsius{instance="$node",job="$job",sensor="temp1"}',
        'node_hwmon_temp_celsius{instance="$node",job="$job",sensor=~"temp[0-9]"}',
        'node_hwmon_temp_celsius{instance="$node",job="$job",chip=~"thermal|cpu|coretemp|k10temp|zenpower|acpitz"}',
        'node_hwmon_temp_celsius{instance="$node",job="$job"}',
        "node_hwmon_temp_celsius",
    ])

    # If still nothing or 0, do a broad scan and pick the *highest* reported sensor (good for multi-core/WSL package+core temps)
    if not temp or temp <= 0:
        for broad_expr in [
            'node_hwmon_temp_celsius{instance="$node",job="$job"}',
            'node_hwmon_temp_celsius',
            'node_thermal_zone_temp',
        ]:
            d = query_prometheus_latest(_prep_prom(broad_expr))
            if d and d.get("data", {}).get("result"):
                vals = []
                for r in d["data"]["result"]:
                    v = _extract_scalar({"data": {"result": [r]}})
                    if v and v > 0:
                        vals.append(v)
                if vals:
                    temp = max(vals)
                    break

    uptime_s = prom_scalar('node_time_seconds{instance="$node",job="$job"} - node_boot_time_seconds{instance="$node",job="$job"}')

    cpu_cores = prom_scalar(
        'count(count(node_cpu_seconds_total{instance="$node",job="$job"}) by (cpu)) * (1 - avg(rate(node_cpu_seconds_total{instance="$node",job="$job",mode="idle"}[30s])))'
    )

    # Base values for context
    cores = prom_scalar('count(count(node_cpu_seconds_total{instance="$node",job="$job"}) by (cpu))')
    ram_total = prom_scalar('node_memory_MemTotal_bytes{instance="$node",job="$job"}')
    cores_str = f"{int(cores)} cores" if cores else "?"
    ram_gb = (ram_total / 1e9) if ram_total else 0
    ram_str = f"{ram_gb:.1f} GB" if ram_gb else "?"

    # Actual RAM used (in GB), not percentage
    ram_used = prom_scalar(
        'node_memory_MemTotal_bytes{instance="$node",job="$job"} - node_memory_MemAvailable_bytes{instance="$node",job="$job"}'
    ) / 1e9

    rootfs_free = _pick_rootfs_bytes("avail")

    dio = _get_disk_io_now()

    # Use slightly uneven columns + short labels + help tooltips so long device lists / values don't overflow or wrap badly in narrow cards.
    c1, c2, c3, c4, c5, c6 = st.columns([1, 1, 1.05, 1.05, 1.15, 1.15])
    with c1:
        st.metric("Temp", f"{temp:.1f} °C" if temp else "—", help="Highest reported sensor (works on Raspberry Pi hwmon/thermal + generic Linux/WSL laptops via coretemp etc). — if no sensors exposed.")
    with c2:
        st.metric("Uptime", f"{uptime_s/86400:.1f} d" if uptime_s else "—")
    with c3:
        gauge_chart(round(cpu_cores or 0, 2), f"CPU cores consumed", min_val=0, max_val=cores or 16, unit=" cores", height=150)
    with c4:
        gauge_chart(round(ram_used or 0, 2), f"RAM used", min_val=0, max_val=ram_gb or 8, unit=" GB", height=150)
    with c5:
        st.metric("Root free", f"{rootfs_free/1e9:.2f} GB" if rootfs_free else "—",
                  help="node_filesystem_avail_bytes for mountpoint=/ (tolerant device/fs match)")
    with c6:
        if dio:
            # Compact primary value; full per-device detail in tooltip so it never overflows the narrow column
            primary_val = next((v for m, v in dio if m.get("device") in ("mmcblk0", "mmcblk0p2")), dio[0][1] if dio else 0)
            dev_list = " ".join([f"{m.get('device','?')}:{int(v)}" for m, v in dio])
            st.metric("Disk IO", f"{int(primary_val)}", help=f"In-flight I/Os now: {dev_list}")
        else:
            st.metric("Disk IO", "—", help="node_disk_io_now (mmcblk0 + partitions)")

    dfs_disk = []
    try:
        import requests as _req
        import time as _time
        now = int(_time.time())
        short_start = now - 10 * 60
        step = "15s"
        base = (PROMETHEUS_URL or "http://172.17.0.1:9090").rstrip("/")
        for metric_name, leg_prefix in [("node_disk_written_bytes_total", "w"), ("node_disk_read_bytes_total", "r")]:
            expr = _prep_prom(f'rate({metric_name}{{instance="$node",job="$job",device=~"mmcblk.*|sd.*|nvme.*|root"}}[2m])')
            r = _req.get(
                f"{base}/api/v1/query_range",
                params={"query": expr, "start": short_start, "end": now, "step": step},
                timeout=12,
            )
            if r.status_code == 200:
                data = r.json()
                for s in data.get("data", {}).get("result", []):
                    dev = s.get("metric", {}).get("device", "?")
                    df = prom_to_df({"data": {"result": [s]}}, [f"{leg_prefix} {dev}"])
                    if df is not None:
                        dfs_disk.append(df)
    except Exception:
        # Fallback to (possibly longer) sidebar-controlled query if direct call fails
        d_w = query_prometheus(_prep_prom('rate(node_disk_written_bytes_total{instance="$node",job="$job",device=~"mmcblk.*|sd.*|nvme.*|root"}[2m])'))
        d_r = query_prometheus(_prep_prom('rate(node_disk_read_bytes_total{instance="$node",job="$job",device=~"mmcblk.*|sd.*|nvme.*|root"}[2m])'))
        for data_src, pfx in [(d_w, "w"), (d_r, "r")]:
            if data_src:
                for s in data_src.get("data", {}).get("result", []):
                    dev = s.get("metric", {}).get("device", "?")
                    df = prom_to_df({"data": {"result": [s]}}, [f"{pfx} {dev}"])
                    if df is not None:
                        dfs_disk.append(df)

    if dfs_disk:
        comb = pd.concat(dfs_disk)
        comb["value"] = comb["value"] / (1024 * 1024)
        # Force the x-range of *only this status chart* to the live window so that
        # an old date selected in the sidebar doesn't clip the live points away.
        _u = None
        _old_sd = _old_ed = None
        try:
            from .. import utils as _u
            import datetime as _dt
            _old_sd, _old_ed = _u.start_dt, _u.end_dt
            _now = _dt.datetime.now()
            _u.start_dt = _now - _dt.timedelta(minutes=12)
            _u.end_dt = _now
            line_chart(comb, "Disk RW (MB/s, live ~10m)", y_label="MB/s", height=200)
        finally:
            if _u is not None and _old_sd is not None:
                _u.start_dt, _u.end_dt = _old_sd, _old_ed
    else:
        _no_data_placeholder("Disk RW")

    proc_run = prom_scalar('node_procs_running{instance="$node",job="$job"}')
    proc_blk = prom_scalar('node_procs_blocked{instance="$node",job="$job"}')
    swap_pct = prom_scalar(
        '(((node_memory_SwapTotal_bytes{instance="$node",job="$job"} - node_memory_SwapFree_bytes{instance="$node",job="$job"}) / node_memory_SwapTotal_bytes{instance="$node",job="$job"}) * 100)'
    )
    iowait = prom_scalar(
        'sum by (instance)(irate(node_cpu_seconds_total{instance="$node",job="$job",mode="iowait"}[1m]))'
    )

    fs_size = _pick_rootfs_bytes("size")
    fs_avail2 = _pick_rootfs_bytes("avail")  # may be same series as the top one
    fs_used = (fs_size - fs_avail2) if (fs_size and fs_avail2 and fs_size > fs_avail2) else 0

    r1, r2, r3, r4 = st.columns(4)
    with r1:
        # Compact value so it fits the column width; full words in help
        st.metric("Procs", f"R:{int(proc_run or 0)} B:{int(proc_blk or 0)}",
                  help="node_procs_running / node_procs_blocked (current)")
    with r2:
        st.metric("Swap", f"{swap_pct:.1f} %" if swap_pct else "—")
    with r3:
        st.metric("IOWait cores", f"{iowait:.2f}" if iowait else "—",
                  help="irate iowait cores over 1m")
    with r4:
        if fs_size and fs_size > 0:
            used_g = fs_used / 1e9
            tot_g = fs_size / 1e9
            # Short metric label + value so it fits; progress gives the visual "bargauge"
            st.metric("Root FS", f"{used_g:.1f}/{tot_g:.1f} GB")
            pctu = min(max((fs_used / fs_size), 0.0), 1.0)
            st.progress(pctu, text=f"{pctu*100:.0f}% used")
        else:
            st.metric("Root FS", "—", help="Tolerant lookup for / mount (device=/dev/root or mmcblk root partition)")

    # ── Containers Monitoring (per user request: count first, then the two current graphs, table last) ──
    section("Containers Monitoring")

    # Active Containers count — placed first under the section.
    # Only count containers that cAdvisor has seen recently (last 2 minutes).
    # This reflects the actual live Docker services that are currently running,
    # instead of stale series that can linger in Prometheus after a container is stopped.
    cont_count = 0
    cd = query_prometheus_current(_prep_prom('count(container_last_seen{instance="$node",job="$job",name=~".+"} > (time() - 120))'))
    cont_count = int(_extract_scalar(cd)) if cd else 0
    if not cont_count:
        cd = query_prometheus_current('count(container_last_seen{name=~".+"} > (time() - 120))')
        cont_count = int(_extract_scalar(cd)) if cd else 0

    st.metric("Active Containers", cont_count if cont_count else "—", help="count(container_last_seen{name=~\".+\"} > (time() - 120)) — only recently active containers")

    # CPU cores per container (current) — uncached for immediate reflection of docker state
    cpu_cont_latest = query_prometheus_current(_prep_prom(
        'sort_desc(sum by(name) (rate(container_cpu_usage_seconds_total{instance="$node",job="$job",name=~".+"}[1m])))'
    ))
    if not cpu_cont_latest or not cpu_cont_latest.get("data", {}).get("result"):
        cpu_cont_latest = query_prometheus_current(
            'sort_desc(sum by(name) (rate(container_cpu_usage_seconds_total{name=~".+"}[1m])))'
        )

    cpu_cont_rows = []
    if cpu_cont_latest and cpu_cont_latest.get("data", {}).get("result"):
        for r in cpu_cont_latest["data"]["result"]:
            m = r.get("metric", {})
            nm = (m.get("name") or m.get("container_name") or m.get("id") or "?").lstrip("/").replace("iot-", "")[:22]
            val = _extract_scalar({"data": {"result": [r]}})
            cpu_cont_rows.append({"series": nm, "value": round(val, 2)})

    if cpu_cont_rows:
        df_cc = pd.DataFrame(cpu_cont_rows)
        horizontal_bar_chart(df_cc, "CPU cores used per container", y_label="cores", height=200)
    else:
        _no_data_placeholder("CPU per container")

    # Memory per container (current, MiB)
    mem_cont_latest = query_prometheus_current(_prep_prom(
        'sort_desc( sum by(name) (container_memory_working_set_bytes{instance="$node",job="$job",name=~".+"}) / 1024 / 1024 )'
    ))
    if not mem_cont_latest or not mem_cont_latest.get("data", {}).get("result"):
        mem_cont_latest = query_prometheus_current(
            'sort_desc( sum by(name) (container_memory_working_set_bytes{name=~".+"}) / 1024 / 1024 )'
        )

    mem_cont_rows = []
    if mem_cont_latest and mem_cont_latest.get("data", {}).get("result"):
        for r in mem_cont_latest["data"]["result"]:
            m = r.get("metric", {})
            nm = (m.get("name") or m.get("container_name") or m.get("id") or "?").lstrip("/").replace("iot-", "")[:22]
            val = _extract_scalar({"data": {"result": [r]}})
            mem_cont_rows.append({"series": nm, "value": round(val, 1)})

    if mem_cont_rows:
        df_memc = pd.DataFrame(mem_cont_rows)
        horizontal_bar_chart(df_memc, f"Memory per container (MiB)", y_label="MiB", height=180)
    else:
        _no_data_placeholder("Memory per container")

    # Gateway Services Usage table (cAdvisor) — placed last under Containers Monitoring as requested
    known_services = ["nodered", "mosquitto", "haproxy", "node-exporter", "promtail", "sync-config", "cadvisor"]

    with st.spinner("Loading service metrics…"):
        try:
            inst = node_instance

            def _fetch_cadvisor(expr_with_inst: str, expr_without: str):
                d = query_prometheus_current(expr_with_inst)
                if d and d.get("data", {}).get("result"):
                    return d
                return query_prometheus_current(expr_without)

            cpu_with = f'sum by (container_label_com_docker_compose_service, name, container_name) (rate(container_cpu_usage_seconds_total{{instance="{inst}"}}[1m]))'
            cpu_without = 'sum by (container_label_com_docker_compose_service, name, container_name) (rate(container_cpu_usage_seconds_total[1m]))'
            cpu_d = _fetch_cadvisor(cpu_with, cpu_without)

            mem_with = f'sum by (container_label_com_docker_compose_service, name, container_name) (container_memory_working_set_bytes{{instance="{inst}"}})'
            mem_without = 'sum by (container_label_com_docker_compose_service, name, container_name) (container_memory_working_set_bytes)'
            mem_d = _fetch_cadvisor(mem_with, mem_without)

            netrx_with = f'sum by (container_label_com_docker_compose_service, name, container_name) (rate(container_network_receive_bytes_total{{instance="{inst}"}}[5m]))'
            netrx_without = 'sum by (container_label_com_docker_compose_service, name, container_name) (rate(container_network_receive_bytes_total[5m]))'
            netrx_d = _fetch_cadvisor(netrx_with, netrx_without)

            nettx_with = f'sum by (container_label_com_docker_compose_service, name, container_name) (rate(container_network_transmit_bytes_total{{instance="{inst}"}}[5m]))'
            nettx_without = 'sum by (container_label_com_docker_compose_service, name, container_name) (rate(container_network_transmit_bytes_total[5m]))'
            nettx_d = _fetch_cadvisor(nettx_with, nettx_without)

            def _normalize_svc(m: dict) -> str:
                if not m:
                    return ""
                for key in [
                    "container_label_com_docker_compose_service",
                    "container_label_com_docker_compose_container",
                    "container_name",
                ]:
                    val = m.get(key)
                    if val:
                        val = val.lstrip("/")
                        if val.startswith("iot-"):
                            val = val[4:]
                        for ks in known_services:
                            if val == ks or ks in val:
                                return ks
                        return val or "unknown"
                n = (m.get("name") or m.get("container") or "").lstrip("/")
                if n.startswith("iot-"):
                    n = n[4:]
                for ks in known_services:
                    if ks in n or n == ks:
                        return ks
                return n or "unknown"

            svc_usage: dict[str, dict] = {
                svc: {"Service": svc, "cpu": 0.0, "mem_mib": 0.0, "net_rx_kib": 0.0, "net_tx_kib": 0.0}
                for svc in known_services
            }

            for dset, metric_key, scale, rnd in [
                (cpu_d, "cpu", 1.0, 2),
                (mem_d, "mem_mib", 1.0 / (1024 * 1024), 1),
                (netrx_d, "net_rx_kib", 1.0 / 1024, 2),
                (nettx_d, "net_tx_kib", 1.0 / 1024, 2),
            ]:
                if not dset or not dset.get("data", {}).get("result"):
                    continue
                for r in dset["data"]["result"]:
                    m = r.get("metric", {})
                    svc = _normalize_svc(m)
                    if not svc:
                        continue
                    if svc not in svc_usage:
                        svc_usage[svc] = {"Service": svc, "cpu": 0.0, "mem_mib": 0.0, "net_rx_kib": 0.0, "net_tx_kib": 0.0}
                    val = _extract_scalar({"data": {"result": [r]}}) * scale
                    svc_usage[svc][metric_key] = round(val, rnd)

            df = pd.DataFrame(list(svc_usage.values()))
            df = df[["Service", "cpu", "mem_mib", "net_rx_kib", "net_tx_kib"]]
            df.columns = ["Service", "CPU cores (current)", "Mem (MiB)", "Net Rx (KiB/s)", "Net Tx (KiB/s)"]
            df = df.sort_values("CPU cores (current)", ascending=False)

            st.dataframe(df, use_container_width=True, hide_index=True)

        except Exception as e:
            st.warning(f"Failed to load Docker service usage: {e}")

    # Per-container timeseries tabs (CPU / Mem / Net / FS) — modeled on grafana panels
    tcpu, tmem, tnet, tfs = st.tabs(["CPU usage per container", "Memory per container", "Network Traffic per container", "FS I/O per container"])

    with tcpu:
        d = query_prometheus(_prep_prom('sum by (name) (rate(container_cpu_usage_seconds_total{instance="$node",job="$job",name=~".+"}[$__rate_interval]))'))
        if not d or not d.get("data", {}).get("result"):
            d = query_prometheus('sum by (name) (rate(container_cpu_usage_seconds_total{name=~".+"}[5m]))')
        dfs = []
        if d:
            for s in d.get("data", {}).get("result", []):
                nm = (s.get("metric", {}).get("name") or "?").lstrip("/").replace("iot-", "")[:18]
                df = prom_to_df({"data": {"result": [s]}}, [nm])
                if df is not None:
                    dfs.append(df)
        if dfs:
            line_chart(pd.concat(dfs), "CPU usage per container (cores)", y_label="cores", height=240)
        else:
            _no_data_placeholder("container cpu")

    with tmem:
        d = query_prometheus(_prep_prom('container_memory_usage_bytes{instance="$node",job="$job",name=~".+"} / 1024 / 1024'))
        if not d or not d.get("data", {}).get("result"):
            d = query_prometheus('container_memory_usage_bytes{name=~".+"} / 1024 / 1024')
        dfs = []
        if d:
            for s in list(d.get("data", {}).get("result", []))[:6]:
                nm = (s.get("metric", {}).get("name") or "?").lstrip("/").replace("iot-", "")[:18]
                df = prom_to_df({"data": {"result": [s]}}, [nm])
                if df is not None:
                    dfs.append(df)
        if dfs:
            line_chart(pd.concat(dfs), f"Used Memory per container (MiB of {ram_str} host)", y_label="MiB", height=240)
        else:
            _no_data_placeholder("container mem")

    with tnet:
        dfs = []
        drx = query_prometheus(_prep_prom('rate(container_network_receive_bytes_total{instance="$node",job="$job",name=~".+"}[$__rate_interval])'))
        if not drx or not drx.get("data", {}).get("result"):
            drx = query_prometheus('rate(container_network_receive_bytes_total{name=~".+"}[5m])')
        if drx:
            for s in list(drx.get("data", {}).get("result", []))[:4]:
                nm = (s.get("metric", {}).get("name") or "?").lstrip("/").replace("iot-", "")[:14]
                df = prom_to_df({"data": {"result": [s]}}, [f"rx-{nm}"])
                if df is not None:
                    dfs.append(df)
        dtx = query_prometheus(_prep_prom('rate(container_network_transmit_bytes_total{instance="$node",job="$job",name=~".+"}[$__rate_interval])'))
        if not dtx or not dtx.get("data", {}).get("result"):
            dtx = query_prometheus('rate(container_network_transmit_bytes_total{name=~".+"}[5m])')
        if dtx:
            for s in list(dtx.get("data", {}).get("result", []))[:4]:
                nm = (s.get("metric", {}).get("name") or "?").lstrip("/").replace("iot-", "")[:14]
                df = prom_to_df({"data": {"result": [s]}}, [f"tx-{nm}"])
                if df is not None:
                    dfs.append(df)
        if dfs:
            comb = pd.concat(dfs)
            comb["value"] = comb["value"] / 1024.0
            line_chart(comb, "Net per container (KiB/s)", y_label="KiB/s", height=240)
        else:
            _no_data_placeholder("container net")

    with tfs:
        dfs = []
        dr = query_prometheus(_prep_prom('rate(container_fs_reads_bytes_total{instance="$node",job="$job",name=~".+"}[$__rate_interval])'))
        if not dr or not dr.get("data", {}).get("result"):
            dr = query_prometheus('rate(container_fs_reads_bytes_total{name=~".+"}[5m])')
        if dr:
            for s in list(dr.get("data", {}).get("result", []))[:4]:
                nm = (s.get("metric", {}).get("name") or "?").lstrip("/").replace("iot-", "")[:14]
                df = prom_to_df({"data": {"result": [s]}}, [f"read {nm}"])
                if df is not None:
                    dfs.append(df)
        dw = query_prometheus(_prep_prom('rate(container_fs_writes_bytes_total{instance="$node",job="$job",name=~".+"}[$__rate_interval])'))
        if not dw or not dw.get("data", {}).get("result"):
            dw = query_prometheus('rate(container_fs_writes_bytes_total{name=~".+"}[5m])')
        if dw:
            for s in list(dw.get("data", {}).get("result", []))[:4]:
                nm = (s.get("metric", {}).get("name") or "?").lstrip("/").replace("iot-", "")[:14]
                df = prom_to_df({"data": {"result": [s]}}, [f"write {nm}"])
                if df is not None:
                    dfs.append(df)
        if dfs:
            comb = pd.concat(dfs)
            comb["value"] = comb["value"] / (1024*1024)
            line_chart(comb, "Container FS I/O (MB/s)", y_label="MB/s", height=240)
        else:
            _no_data_placeholder("container fs io")

    # ── Hardware Monitoring ──
    section("Hardware Monitoring")

    # CPU
    section("CPU Usage (detailed)")
    tabc1, tabc2 = st.tabs(["Overview", "By mode"])
    with tabc1:
        legends = ["Busy System", "Busy User", "Busy Iowait", "Busy IRQs", "Idle"]
        exprs = [
            'sum(rate(node_cpu_seconds_total{instance="$node",job="$job", mode="system"}[$__rate_interval]))',
            'sum(rate(node_cpu_seconds_total{instance="$node",job="$job", mode="user"}[$__rate_interval]))',
            'sum(rate(node_cpu_seconds_total{instance="$node",job="$job", mode="iowait"}[$__rate_interval]))',
            'sum(sum without(mode) (rate(node_cpu_seconds_total{instance="$node",job="$job", mode=~".*irq"}[$__rate_interval])))',
            'sum(rate(node_cpu_seconds_total{instance="$node",job="$job", mode="idle"}[$__rate_interval]))',
        ]
        dfs = []
        for expr, leg in zip(exprs, legends):
            d = query_prometheus(_prep_prom(expr))
            df = prom_to_df(d, [leg])
            if df is not None: dfs.append(df)
        if dfs:
            comb = pd.concat(dfs)
            line_chart(comb, "CPU Usage Over Time (cores)", y_label="cores", height=260)
        else:
            _no_data_placeholder("cpu")
    with tabc2:
        legends2 = ["System", "User", "Nice", "Iowait", "Irq", "Softirq", "Idle"]
        exprs2 = [
            'sum(rate(node_cpu_seconds_total{mode="system",instance="$node",job="$job"}[$__rate_interval]))',
            'sum(rate(node_cpu_seconds_total{mode="user",instance="$node",job="$job"}[$__rate_interval]))',
            'sum(rate(node_cpu_seconds_total{mode="nice",instance="$node",job="$job"}[$__rate_interval]))',
            'sum(rate(node_cpu_seconds_total{mode="iowait",instance="$node",job="$job"}[$__rate_interval]))',
            'sum(rate(node_cpu_seconds_total{mode="irq",instance="$node",job="$job"}[$__rate_interval]))',
            'sum(rate(node_cpu_seconds_total{mode="softirq",instance="$node",job="$job"}[$__rate_interval]))',
            'sum(rate(node_cpu_seconds_total{mode="idle",instance="$node",job="$job"}[$__rate_interval]))',
        ]
        dfs = []
        for expr, leg in zip(exprs2, legends2):
            d = query_prometheus(_prep_prom(expr))
            df = prom_to_df(d, [leg])
            if df is not None: dfs.append(df)
        if dfs:
            comb = pd.concat(dfs)
            line_chart(comb, "CPU Detailed by mode (cores)", y_label="cores", height=260)
        else:
            _no_data_placeholder("cpu detailed")

    # Memory
    section("Memory (detailed)")
    mem_legends = ["Total", "Used", "Cache+Buffer", "Free", "Swap"]
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
        comb = pd.concat(dfs)
        comb["value"] = comb["value"] / 1e9
        line_chart(comb, f"Memory (GB)", y_label="GB", height=240)
    else:
        _no_data_placeholder("mem")

    # Network
    section("Network (detailed)")
    d_rx = query_prometheus(_prep_prom('rate(node_network_receive_bytes_total{instance="$node",job="$job"}[$__rate_interval])*8'))
    d_tx = query_prometheus(_prep_prom('rate(node_network_transmit_bytes_total{instance="$node",job="$job"}[$__rate_interval])*8'))
    dfs = []
    if d_rx:
        for s in d_rx.get("data", {}).get("result", []):
            dev = s.get("metric", {}).get("device", "if")
            df = prom_to_df({"data": {"result": [s]}}, [f"Rx {dev}"])
            if df is not None: dfs.append(df)
    if d_tx:
        for s in d_tx.get("data", {}).get("result", []):
            dev = s.get("metric", {}).get("device", "if")
            df = prom_to_df({"data": {"result": [s]}}, [f"Tx {dev}"])
            if df is not None: dfs.append(df)
    if dfs:
        comb = pd.concat(dfs)
        comb["value"] = comb["value"] / 1e6
        line_chart(comb, "Network (Mbps)", y_label="Mbps", height=220)
    else:
        _no_data_placeholder("net")

    # Disk detailed
    section("Disk / Storage (detailed)")
    d_sp = query_prometheus(_prep_prom(
        '((node_filesystem_size_bytes{instance="$node",job="$job",device!~"rootfs"} - node_filesystem_avail_bytes{instance="$node",job="$job",device!~"rootfs"}) / node_filesystem_size_bytes{instance="$node",job="$job",device!~"rootfs"}) * 100'
    ))
    if d_sp and d_sp.get("data", {}).get("result"):
        dfs = []
        for s in d_sp.get("data", {}).get("result", []):
            mp = s.get("metric", {}).get("mountpoint", "fs")
            df = prom_to_df({"data": {"result": [s]}}, [mp])
            if df is not None: dfs.append(df)
        if dfs:
            line_chart(pd.concat(dfs), "Filesystem Used %", y_label="%", height=200)

    # Disk throughput + iops in subcols
    dc1, dc2 = st.columns(2)
    with dc1:
        dr = query_prometheus(_prep_prom('rate(node_disk_read_bytes_total{instance="$node",job="$job",device=~"[a-z]+|nvme.*"}[$__rate_interval])'))
        dw = query_prometheus(_prep_prom('rate(node_disk_written_bytes_total{instance="$node",job="$job",device=~"[a-z]+|nvme.*"}[$__rate_interval])'))
        dfs = []
        for data_src, pfx in [(dr, "r"), (dw, "w")]:
            if data_src:
                for s in data_src.get("data", {}).get("result", []):
                    dev = s.get("metric", {}).get("device", "?")
                    df = prom_to_df({"data": {"result": [s]}}, [f"{pfx}-{dev}"])
                    if df is not None: dfs.append(df)
        if dfs:
            comb = pd.concat(dfs)
            comb["value"] /= 1e6
            line_chart(comb, "Disk Throughput (MB/s)", y_label="MB/s", height=200)
    with dc2:
        dri = query_prometheus(_prep_prom('rate(node_disk_reads_completed_total{instance="$node",job="$job",device=~"[a-z]+|nvme.*"}[$__rate_interval])'))
        dwi = query_prometheus(_prep_prom('rate(node_disk_writes_completed_total{instance="$node",job="$job",device=~"[a-z]+|nvme.*"}[$__rate_interval])'))
        dfs = []
        for data_src, pfx in [(dri, "riops"), (dwi, "wiops")]:
            if data_src:
                for s in data_src.get("data", {}).get("result", []):
                    dev = s.get("metric", {}).get("device", "?")
                    df = prom_to_df({"data": {"result": [s]}}, [f"{pfx}-{dev}"])
                    if df is not None: dfs.append(df)
        if dfs:
            line_chart(pd.concat(dfs), "Disk I/O Ops", y_label="ops/s", height=200)

    # Temp sensors full
    section("All Temperature Sensors")
    d = query_prometheus(_prep_prom('node_hwmon_temp_celsius{instance="$node",job="$job"}'))
    if d and d.get("data", {}).get("result"):
        dfs = []
        for s in d.get("data", {}).get("result", []):
            chip = s.get("metric", {}).get("chip", "?")
            sensor = s.get("metric", {}).get("sensor", "?")
            df = prom_to_df({"data": {"result": [s]}}, [f"{chip}/{sensor}"])
            if df is not None: dfs.append(df)
        if dfs:
            line_chart(pd.concat(dfs), "HWMon Temperature (°C)", y_label="°C", height=200)
        else:
            _no_data_placeholder("hwmon temp")
    else:
        _no_data_placeholder("temp sensors")
