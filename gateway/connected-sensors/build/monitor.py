#!/usr/bin/env python3
"""
Live connected sensors monitor.

Tails mosquitto.log (using tail -F for robustness) and maintains the exact
set of sensor users that currently have an open session according to the
broker's own log lines.

Writes /textfile/active_sensors.prom (Prometheus textfile format) on changes.
This gives the dashboard (via query_prometheus_latest) and Grafana a true
"currently connected" view with no time window / duration.

The service reacts immediately to "New client connected ... u'sensorX'" and
the corresponding "Received DISCONNECT from ..." / "Client ... disconnected."
"""

import os
import re
import subprocess
import sys
import threading
import time
from pathlib import Path

LOG_PATH = Path("/mosquitto/log/mosquitto.log")
TEXTFILE_DIR = Path("/textfile")
OUT_PATH = TEXTFILE_DIR / "active_sensors.prom"
TMP_PATH = OUT_PATH.with_suffix(".prom.tmp")

CONN_RE = re.compile(
    r"New client connected from ([\d.]+):\d+ as ([^\s(]+).*u'([^']+)'"
)
DISC_RE = re.compile(
    r"(?:Received DISCONNECT from ([^\s(]+)|Client ([^\s[]+).*disconnected)"
)
PUBLISH_SENSOR_RE = re.compile(
    r"Received PUBLISH from ([^\s(]+).*'sensors/([^/]+)/process'"
)

INACTIVITY_TIMEOUT = 60  # seconds without a data publish before a sensor is dropped from "currently sending" (fallback for unclean disconnects)

# sensor (e.g. "sensor4") -> last publish timestamp (for inactivity tracking)
active_senders: dict[str, float] = {}
# client_id -> sensor (for mapping during bursts)
client_to_user: dict[str, str] = {}
# sensor -> last known connection info for richer display in prom
last_info: dict[str, dict] = {}


def write_metrics():
    now = time.time()
    # only include sensors whose last publish is within the inactivity window
    current = {
        s: ts for s, ts in active_senders.items()
        if now - ts <= INACTIVITY_TIMEOUT
    }

    # prune expired from our dicts
    for s in list(active_senders.keys()):
        if s not in current:
            active_senders.pop(s, None)
            last_info.pop(s, None)

    lines = [
        "# HELP mqtt_connected_sensor 1 while this sensor has recently sent data (active sender)",
        "# TYPE mqtt_connected_sensor gauge",
    ]
    for sensor in sorted(current.keys()):
        info = last_info.get(sensor, {})
        cid = info.get("client", "")
        ip = info.get("ip", "")
        lines.append(
            f'mqtt_connected_sensor{{device_id="{sensor}",client_id="{cid}",source_ip="{ip}"}} 1'
        )

    lines.append("# HELP mqtt_connected_sensor_count Number of distinct sensors that have recently sent data")
    lines.append("# TYPE mqtt_connected_sensor_count gauge")
    lines.append(f"mqtt_connected_sensor_count {len(current)}")

    try:
        TEXTFILE_DIR.mkdir(parents=True, exist_ok=True)
        with open(TMP_PATH, "w") as f:
            f.write("\n".join(lines) + "\n")
        os.replace(TMP_PATH, OUT_PATH)

        # Emit full current state as structured JSON log to Loki (via promtail).
        # This allows Streamlit (monitoring stack) to query the exact state at a specific past timestamp.
        try:
            import json
            from datetime import datetime, timezone
            state_log = {
                "@timestamp": datetime.now(timezone.utc).isoformat(),
                "event_type": "state_snapshot",
                "state_type": "connected_sensors",
                "sensors": list(current.keys()),
                "details": {s: last_info.get(s, {}) for s in current}
            }
            log_path = Path("/var/log/iot-gateway/gateway-state.log")
            log_path.parent.mkdir(parents=True, exist_ok=True)
            with open(log_path, "a") as f:
                f.write(json.dumps(state_log) + "\n")
        except Exception as ex:
            print(f"[connected-sensors] gateway-state log error: {ex}", flush=True)
    except Exception as ex:
        print(f"[connected-sensors] write error: {ex}", flush=True)


def seed_from_recent_tail(max_lines: int = 800):
    """Bootstrap from the end of the current log so we have a good picture
    of sessions that were established before this monitor started.
    Only seeds; live tailing owns all future add/remove decisions.
    """
    if not LOG_PATH.exists():
        return
    try:
        # Efficient: ask tail for only the recent lines
        res = subprocess.run(
            ["tail", "-n", str(max_lines), str(LOG_PATH)],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if res.returncode != 0:
            return
        lines = res.stdout.splitlines()
    except Exception:
        return

    events = []
    for line in lines:
        m = CONN_RE.search(line)
        if m:
            ip, cid, user = m.group(1), m.group(2), m.group(3)
            events.append(("connect", cid, user, ip))
            continue
        m = DISC_RE.search(line)
        if m:
            cid = m.group(1) or m.group(2)
            if cid:
                events.append(("disconnect", cid, None, None))

    for typ, cid, user, ip in events:
        if typ == "connect" and user:
            last_info[user] = {"client": cid, "ip": ip}
            if cid:
                client_to_user[cid] = user
        elif typ == "disconnect" and cid:
            client_to_user.pop(cid, None)

    # Seed active senders from recent PUBLISH lines in the log tail.
    # This is the main signal for "sensors that are (or were recently) sending data".
    for line in lines:
        m = PUBLISH_SENSOR_RE.search(line)
        if m:
            cid, sensor = m.group(1), m.group(2)
            active_senders[sensor] = time.time()  # treat as recently active at monitor start
            if cid:
                client_to_user[cid] = sensor
            if sensor not in last_info:
                last_info[sensor] = {"client": cid, "ip": ""}

    if active_senders:
        print(f"[connected-sensors] seeded with {len(active_senders)} recently active senders from recent publishes: {sorted(active_senders.keys())}", flush=True)
        write_metrics()


def process_line(line: str) -> bool:
    """Return True if the set of recently active senders changed (so caller can log the current list)."""
    line = line.rstrip("\n")
    changed = False

    # Connection events (useful for logging "who is connecting" and enriching client/IP in the prom output)
    m = CONN_RE.search(line)
    if m:
        ip, cid, user = m.group(1), m.group(2), m.group(3)
        if user:
            prev = last_info.get(user)
            last_info[user] = {"client": cid, "ip": ip}
            if cid:
                client_to_user[cid] = user
            if not prev or prev.get("client") != cid:
                changed = True
                print(f"[connected-sensors] CONNECT  user={user}  client={cid}  ip={ip}", flush=True)

    # Disconnect: immediately remove from active senders so the "currently connected"
    # metric reflects the broker's current session state right away (no 120s wait).
    m = DISC_RE.search(line)
    if m:
        cid = m.group(1) or m.group(2)
        if cid:
            user = client_to_user.pop(cid, None)
            if user:
                print(f"[connected-sensors] DISCONNECT  user={user}  client={cid}", flush=True)
                if user in active_senders:
                    active_senders.pop(user, None)
                    last_info.pop(user, None)
                    changed = True

    # PUBLISH of sensor data - this is the primary signal that a sensor is (or was just) sending data
    m = PUBLISH_SENSOR_RE.search(line)
    if m:
        cid, sensor = m.group(1), m.group(2)
        prev_ts = active_senders.get(sensor, 0)
        now = time.time()
        active_senders[sensor] = now

        # Enrich last known client info (so the prom table can show Client ID / Source IP when available)
        info = last_info.setdefault(sensor, {})
        if cid:
            info["client"] = cid
            client_to_user[cid] = sensor

        if now - prev_ts > 3:  # avoid log spam on very frequent bursts
            print(f"[connected-sensors] PUBLISH  sensor={sensor}  client={cid}", flush=True)

        changed = True

    if changed:
        write_metrics()

    return changed


def _cleanup_expired() -> bool:
    """Remove senders that have not published data recently.
    Return True if any were expired (so we can rewrite the prom file).
    """
    now = time.time()
    expired = [
        s for s, ts in list(active_senders.items())
        if now - ts > INACTIVITY_TIMEOUT
    ]
    for s in expired:
        active_senders.pop(s, None)
        last_info.pop(s, None)
    return len(expired) > 0


def expiration_cleaner():
    """Background thread: periodically expire inactive senders and refresh the prom file."""
    while True:
        time.sleep(10)
        if _cleanup_expired():
            write_metrics()
            print(
                f"[connected-sensors] active senders now: {sorted(active_senders.keys())}  (count={len(active_senders)})",
                flush=True,
            )


def follow_with_tail():
    """Use tail -F (robust to rotation, handles file replacement)."""
    while True:  # outer restart loop
        if not LOG_PATH.exists():
            print(f"[connected-sensors] waiting for {LOG_PATH} ...", flush=True)
            time.sleep(1)
            continue

        print(f"[connected-sensors] following {LOG_PATH} with tail -F", flush=True)

        proc = subprocess.Popen(
            ["tail", "-n", "0", "-F", str(LOG_PATH)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        try:
            assert proc.stdout is not None
            for line in proc.stdout:
                if process_line(line):
                    print(
                        f"[connected-sensors] active senders now: {sorted(active_senders.keys())}  (count={len(active_senders)})",
                        flush=True,
                    )
            # If we reach here, tail exited (shouldn't with -F unless file gone)
            print("[connected-sensors] tail -F ended, will restart follower...", flush=True)
        except Exception as ex:
            print(f"[connected-sensors] follower error: {ex}", flush=True)
        finally:
            try:
                proc.terminate()
            except Exception:
                pass
        time.sleep(1)


def main():
    print("[connected-sensors] starting live monitor (file tail on mosquitto.log)", flush=True)
    TEXTFILE_DIR.mkdir(parents=True, exist_ok=True)

    seed_from_recent_tail()

    # Write whatever state we have after seeding (even if empty, to have count=0)
    write_metrics()
    if not active_senders:
        print("[connected-sensors] no recently active senders after seed", flush=True)
        print("[connected-sensors] active senders now: []  (count=0)", flush=True)

    # Start background thread that expires sensors with no recent data publishes
    # and keeps the prom file up to date with only currently "sending" sensors.
    cleaner_thread = threading.Thread(target=expiration_cleaner, daemon=True)
    cleaner_thread.start()

    follow_with_tail()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("[connected-sensors] stopping", flush=True)
    except Exception as ex:
        print(f"[connected-sensors] fatal: {ex}", flush=True)
        sys.exit(1)
