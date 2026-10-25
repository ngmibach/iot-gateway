# IoT Gateway Monitor

Cross-platform desktop app: **download → double-click → Setup Wizard → provision gateway agent → Monitoring + Actions**.

No Docker on the operator PC. No WSL required on Windows. No Docker on the gateway.

| Piece | Role |
|-------|------|
| **Desktop app** (Windows `.exe` / Linux AppImage) | Wizard, Actions, Monitoring, Admin |
| **Local Loki + Prometheus** | App-managed native processes (downloaded once in-UI) |
| **Gateway agent** | One systemd service: Mosquitto (MQTT ingress) + Kafka topic store (per sensor) + decrypt → log + metrics + Loki shipper + mDNS |
| **Communication** | SSH for control/provision; MQTT + HTTP for data |

---

## Download & run

[**GitHub Releases — desktop-latest**](https://github.com/ngmibach/iot-gateway/releases/tag/desktop-latest)

| Platform | File | How to run |
|----------|------|------------|
| **Windows** | `IoTGatewayMonitor.exe` | Download → double-click (WSL not required). If SmartScreen says unrecognized: **More info → Run anyway** (sign via Admin → Code Signing for full trust). |
| **Ubuntu / Linux** | `IoTGatewayMonitor-x86_64.AppImage` | `chmod +x` once → double-click |

### First-run Wizard (all in the UI)

1. **Install monitoring** — downloads Loki + Prometheus once and starts them (progress in the Wizard; no Docker). Then **Open app**.
2. Under **Gateways → Registration** — pick MONITORING_IP (LAN), Find gateway (SSH), enter credentials, **Install gateway** (apt packages + agent over SSH; sudo password is not saved on the PC).

App data: Linux `~/.local/share/iot-gateway-monitor/`, Windows `%APPDATA%\IoTGatewayMonitor\`.

---

## Branches

| Branch | Role |
|--------|------|
| **`main`** | Integration + CI workflow |
| **`linux`** | Push → rebuild AppImage → `desktop-latest` |
| **`windows`** | Push → rebuild `.exe` → `desktop-latest` |

---

## Architecture — gateway and monitoring

### High-level layout

```
Operator PC (monitoring)                 Gateway device (e.g. Raspberry Pi)
────────────────────────                 ──────────────────────────────────
IoTGatewayMonitor                          iot-gateway-agent (systemd)
  Wizard / Gateways / Control Plane          ├─ Mosquitto (MQTT :1883)     ← sensor publish
  Monitoring (Metric / Activities)           ├─ Kafka topic store          ← one topic per sensor
  Loki :3100 (native)                        │    retention.bytes = topic cap
  Prometheus :9090 (native)                  ├─ decrypt → sensor_data.log
  registry.sqlite (gateways + devices)       ├─ Loki shipper → PC:3100
                                             ├─ GET :9139/metrics /v1/health
                                             └─ mDNS
```

Sensors publish over MQTT to the gateway. The gateway stores each sensor’s
messages in a dedicated Kafka topic (size-capped), decrypts for the local log,
and ships cleartext lines to the operator Loki. The desktop app scrapes the
agent Prometheus metrics and queries Loki for activities.

### Data path

1. **Sensor → Mosquitto** — TLS/password MQTT on the gateway (`sensors/…` topics).
2. **Mosquitto → Kafka** — each registered sensor owns one Kafka topic
   (`sensor.<device_id>`) with a hard `retention.bytes` cap so retained
   segments cannot grow without bound.
3. **Decrypt + ship** — agent decrypts payloads to `sensor_data.log` and ships
   lines to operator Loki (`MONITORING_IP:3100`).
4. **Monitor** — Prometheus scrapes `iot-gateway-agent` on `:9139`; the desktop
   Monitoring views read Prometheus + Loki through the local control service.

### Sensor registration and Kafka capacity

When a sensor is registered (Control Plane → Registration):

1. The control service probes **total gateway disk** (`df` on the agent data dir).
2. It loads the Kafka topic catalog at
   `/var/lib/iot-gateway-agent/kafka/topics.json`.
3. It reserves a new topic only if capacity remains.
4. It upserts Mosquitto ACL + password hash, signs the client cert, and reloads Mosquitto.
5. Unregister removes the MQTT user and the Kafka catalog entry.

**Capacity formula** (safety headroom for OS, Mosquitto, logs, agent):

```
max_sensors = floor( total_gateway_storage × 0.70 / topic_retention_cap )
```

| Example | Value |
|---------|--------|
| Gateway disk | 10 units |
| Per-topic Kafka retention cap | 1 unit |
| Safety ratio | 70% |
| **Max sensors** | **floor(10 × 0.70 / 1) = 7** |

Only **70%** of gateway storage is budgeted for Kafka topic retention. The other
30% stays free for the OS, Mosquitto, logs, and agent data. Each topic’s
`retention.bytes` equals the per-topic cap so one noisy sensor cannot exhaust
the disk.

API:

- `GET /api/v1/gateways/{id}/kafka/capacity` — current slots / remaining.
- `POST /api/v1/gateways/{id}/devices` — registers MQTT + Kafka topic; returns
  **409** when the gateway is at Kafka capacity.
- Device responses include `kafka_topic` and `kafka_retention_bytes`.

> **Note:** Registration already enforces the catalog and capacity math. A
> Kafka-compatible broker (e.g. Redpanda) on the Pi that applies
> `retention.bytes` from the catalog is the next provisioning step.

### Monitoring stack (operator PC)

| Component | Role |
|-----------|------|
| **Prometheus** `:9090` | Scrapes gateway agent `/metrics` (`job=iot-gateway-agent`, `instance=gateway`) |
| **Loki** `:3100` | Receives shipped sensor log lines from the gateway |
| **Control service** `:9137` | Device registry, SSH playbooks, query APIs |
| **Wizard / UI** `:9138` | Setup, Gateways, Monitoring, Control Plane |

Monitoring tabs: **Gateway Metric** (host + application health), **Gateway Activities**
(gateway + per-sensor Kafka activity), **Control Plane** (sensor Registration + View).

### Gateway Activities

Activities is the operator view of message flow and per-sensor Kafka topics.

1. **Gateway selector** — dropdown shows the gateway **name only** (host/IP is under
   Gateways → Settings).
2. **General information** — Total msgs, Msgs/sec, Denied, IDS, plus a transmission
   delay subsection with a chart (empty-state when no series).
3. **Connected sensors** — table of registry devices: Device, IP, Kafka topic,
   Retention cap, Monitor.
4. **Sensor detail**
   - **One sensor** → a separate detail panel under the table (no tab bar).
   - **Several sensors** → horizontal name tabs to cycle between sensors.
   - Each sensor panel shows Total msgs, Msgs/sec, Denied, IDS; the Kafka topic
     name + retention cap + topic activity chart; and a transmission delay
     subsection with its own chart.

Data: `GET /api/v1/query/summaries/gateway?gateway_id=…&range=…` merges the device
registry (Kafka topic labels) with Prometheus decrypt counters and Loki when
labeled series exist. Chart frames stay visible with “No data in range” until
scrapes fill in.

Deferred Kafka broker metrics and richer per-device counters:
`docs/plan-activities-kafka-followups.md`.

---

## Repository layout

| Path | Purpose |
|------|---------|
| `apps/desktop/` | Packaged UI, wizard shell, Windows/Linux packaging |
| `apps/control-service/` | FastAPI control plane, provisioner, telemetry, actions (incl. Kafka capacity) |
| `gateway/agent/` | Monolithic gateway agent (systemd unit + Python package) |
| `docs/architecture.md` | Short architecture notes |
| `docs/plan-activities-kafka-followups.md` | Deferred Activities / Kafka metrics work |
| `deploy/templates/prometheus.yml` | Scrape template for the agent `/metrics` job |
