# IoT Gateway Monitor

Cross-platform desktop app: **download → double-click → Setup Wizard → provision gateway agent → Monitoring + Actions**.

No Docker on the operator PC. No WSL required on Windows. No Docker on the gateway.

| Piece | Role |
|-------|------|
| **Desktop app** (Windows `.exe` / Linux AppImage) | Wizard, Actions, Monitoring, Admin |
| **Local Loki + Prometheus + Grafana** | App-managed native processes (downloaded once in-UI); Grafana HTTPS on `127.0.0.1:9140` |
| **Gateway agent** | One systemd service: Mosquitto (MQTTS :8883 mTLS ingress) + Kafka topic store (per sensor) + decrypt → log + metrics + Loki shipper + mDNS |
| **Communication** | SSH for control/provision; MQTT + HTTP for data |

---

## Download & run

[**GitHub Releases — desktop-latest**](https://github.com/ngmibach/iot-gateway/releases/tag/desktop-latest)

| Platform | File | How to run |
|----------|------|------------|
| **Windows** | `IoTGatewayMonitor.exe` | Download → double-click (WSL not required). If SmartScreen says unrecognized: **More info → Run anyway** (sign via Admin → Code Signing for full trust). |
| **Ubuntu / Linux** | `IoTGatewayMonitor-x86_64.AppImage` | `chmod +x` once → double-click |

### First-run Wizard (all in the UI)

1. **Install monitoring** — downloads Loki + Prometheus + Grafana once and starts them (progress in the Wizard; no Docker; Grafana ~445 MiB). Then **Open app**.
2. Under **Gateways → Registration** — pick MONITORING_IP (LAN), Find gateway (SSH), enter credentials, **Install gateway** (apt packages + agent over SSH; sudo password is saved in the app keyring for later fake-sensor / cleanup use).

App data: Linux `~/.local/share/iot-gateway-monitor/`, Windows `%APPDATA%\IoTGatewayMonitor\`.

---

## Branches

| Branch | Role |
|--------|------|
| **`main`** | Integration + CI workflow |
| **`linux`** | Push → rebuild AppImage → `desktop-latest` |
| **`windows`** | Push → rebuild `.exe` → `desktop-latest` |

Shared docs/UI changes ship on `windows` then `linux` (`docs(windows):` / `docs(linux):` or feat/fix pairs), then return to `windows`.

---

## Architecture — gateway and monitoring

### High-level layout

```
Operator PC (monitoring)                 Gateway device (e.g. Raspberry Pi)
────────────────────────                 ──────────────────────────────────
IoTGatewayMonitor                          iot-gateway-agent (systemd)
  Wizard / Gateways / Control Plane          ├─ Mosquitto (MQTTS :8883 mTLS)
  Monitoring (Metric / Activities)           │    ← sensor + decrypt worker
  Loki :3100 (native)                        ├─ Kafka topic store          ← one topic per sensor
  Prometheus :9090 (native)                  │    INTERNAL 127.0.0.1:9092 (agent)
  Grafana HTTPS :9140 (native)               │    EXTERNAL {gateway_ip}:9092 (Grafana)
  registry.sqlite (gateways + devices)       │    retention.bytes = topic cap
  keyring (CA passphrases)                   ├─ decrypt → sensor_data.log
  FakeCertRenewer (fakes only)               ├─ Loki shipper → PC:3100
                                             ├─ GET :9139/metrics /v1/health
                                             ├─ mDNS
                                             └─ iotgw-fake bridge / iotgw-fake@ units
                                                  (optional test sensors)
```

Sensors publish over **MQTTS :8883** (password + client certificate) to the
gateway. Plaintext MQTT :1883 is not used for production ingress. The gateway
stores each sensor’s messages in a dedicated Kafka topic (size-capped),
decrypts for the local log, and ships cleartext lines to the operator Loki.
The desktop app scrapes the agent Prometheus metrics and queries Loki for
activities. Gateways → Install creates the gateway CA and server certificate
(and can auto-generate the CA passphrase into the app keyring).

### Data path

1. **Sensor → Mosquitto** — MQTTS :8883 with password + client cert
   (`sensors/…` topics). Decrypt worker uses the same listener with its own
   client cert. Preferred app payload is **envelope v1**: separate stamped
   publishes on `sensors/<id>/env/key` and `sensors/<id>/env/data` (AES-GCM;
   registration provisions device crypto + schema; daily DMEC via
   `GET :9139/v1/crypto/day/current`). Legacy Fernet `{"key","encrypted"}`
   remains accepted until `IOTGW_ENVELOPE_REQUIRE=1`. See
   [`docs/encryption.md`](docs/encryption.md) (reference) and
   [`docs/architecture.md`](docs/architecture.md).
2. **Mosquitto → Kafka** — each registered sensor owns one Kafka topic
   (`sensor.<device_id>`) with a hard `retention.bytes` cap so retained
   segments cannot grow without bound.
3. **Decrypt + ship** — agent decrypts payloads to `sensor_data.log` and ships
   lines to operator Loki (`MONITORING_IP:3100`).
4. **Monitor** — Prometheus scrapes `iot-gateway-agent` on `:9139`; the desktop
   Monitoring views read Prometheus + Loki through the local control service.

### Sensor registration and Kafka capacity

When a sensor is registered (Control Plane → Registration), including
**Create fake sensor**:

1. The control service probes **total gateway disk** (`df` on the agent data dir).
2. It loads the Kafka topic catalog at
   `/var/lib/iot-gateway-agent/kafka/topics.json`.
3. It reserves a new topic only if capacity remains (fakes count toward the same cap).
4. It upserts Mosquitto ACL + password hash, signs the client cert, and reloads Mosquitto.
5. Unregister removes the MQTT user and the Kafka catalog entry (and tears down
   fake netns/units when the device is a fake).

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

> **Note:** Gateway provision installs **Apache Kafka** in minimal KRaft
> single-node mode (`iotgw-kafka`, heap 128–256M) with dual PLAINTEXT listeners —
> INTERNAL `127.0.0.1:9092` and EXTERNAL `{gateway_ip}:9092`. Not Redpanda.
> Re-provision older gateways for LAN Grafana; details in
> [`docs/architecture.md`](docs/architecture.md). Sensor register/unregister
> creates or deletes topics with `retention.bytes` from the catalog. The agent
> produces decrypted payloads to `sensor.<device_id>` after MQTT decrypt.

### Monitoring stack (operator PC)

| Component | Role |
|-----------|------|
| **Prometheus** `:9090` | Scrapes gateway agent `/metrics` (`job=iot-gateway-agent`, `instance=gateway`) |
| **Loki** `:3100` | Receives shipped sensor log lines from the gateway |
| **Grafana** `https://127.0.0.1:9140` | Localhost HTTPS; Prometheus, Loki, and per-gateway Kafka datasources; opens in system browser |
| **Control service** `:9137` | Device registry, SSH playbooks, query APIs |
| **Wizard / UI** `:9138` | Setup, Gateways, Monitoring, Control Plane |

Monitoring tabs: **Gateway Metric** (host + application health), **Gateway Activities**
(gateway + per-sensor Kafka activity), **Control Plane** (Registration | View | Simulate),
plus **Grafana** (opens in the system browser).

### Fake sensors (Control Plane testing)

Operators can spawn **fake sensors on the gateway itself** for MQTTS / Kafka /
Activities testing without extra LAN hardware.

| Step | What happens |
|------|----------------|
| **Registration → Create fake sensor** | Device ID, password, topics — allocates an IP on the private `iotgw-fake` bridge (`10.255.0.0/24`), creates a netns + veth, registers like a real sensor (MQTT user, Kafka topic, CA-signed client cert), feeds certs into the fake runtime, starts `iotgw-fake@<id>`. Uses the gateway sudo password saved at Install (injected by the wizard proxy). If no CA signing password is saved yet, **Generate CA passphrase** reuses that saved sudo (or asks once) |
| **View** | Shows a **Fake** / **Real** badge; fakes show auto-renew status and **Open Simulate** |
| **Simulate** | Fake devices only (after create): Start/Stop, send interval, MQTT topic, payload JSON, lab behavior toggles (omit/wrong client cert, skip/bad encryption, wrong password/topic), cert status line. Sample manufacturing payload: [`docs/samples/fake-sensor-payload.json`](docs/samples/fake-sensor-payload.json) |
| **Cert lifecycle** | The monitoring app **auto-renews and feeds** mTLS material for `is_fake` devices only (real sensors still download a cert zip for the operator). TLS attack toggles pause auto-feed until cleared |
| **Capacity** | Each fake consumes one Kafka capacity slot (same formula as real sensors) |
| **Uninstall / delete** | Deleting a fake tears down its unit + netns; Gateways → Clean up / Settings → Remove tears down **all** `iotgw-fake@*` units, leftover `iotgw-fake-*` netns, and the `iotgw-fake` bridge |

Behavior toggles are for lab/testing only. Privileged netns steps use sudo on the gateway.

### Gateway Activities

Activities is the operator view of message flow and per-sensor Kafka topics.

1. **Gateway selector** — dropdown shows the gateway **name only** (host/IP is under
   Gateways → Settings).
2. **General information** — Total msgs, Msgs/sec, Denied, IDS, plus a transmission
   delay subsection with a chart (empty-state when no series).
3. **Connected sensors** — table of registry devices: Device, **Type** (Fake/Real),
   IP, Kafka topic, Retention cap, Monitor.
4. **Sensor detail**
   - **One sensor** → a separate detail panel under the table (no tab bar).
   - **Several sensors** → horizontal name tabs (with Fake/Real badge) to cycle
     between sensors.
   - Each sensor panel shows Total msgs, Msgs/sec, Denied, IDS; the Kafka topic
     name + retention cap + topic activity chart; and a transmission delay
     subsection with its own chart.

Data: `GET /api/v1/query/summaries/gateway?gateway_id=…&range=…` merges the device
registry (Kafka topic labels + `is_fake`), live `topics.json` catalog sync over SSH,
and Prometheus agent series (`iotgw_decrypt_*`, `iotgw_device_*`, denied/IDS). Loki
legacy queries remain as fallback. Chart frames stay visible with “No data in
range” until scrapes fill in.

Deferred Kafka broker metrics and richer per-device counters:
`docs/plan-activities-kafka-followups.md`.

---

## Repository layout

| Path | Purpose |
|------|---------|
| `apps/desktop/` | Packaged UI, wizard shell, Windows/Linux packaging |
| `apps/control-service/` | FastAPI control plane, provisioner, telemetry, actions (incl. Kafka capacity) |
| `gateway/agent/` | Monolithic gateway agent (systemd unit + Python package) |
| `docs/architecture.md` | Architecture notes (gateway, Kafka, envelope crypto) |
| `docs/encryption.md` | Envelope v1 application encryption reference |
| `docs/plan-encryption-redesign.md` | Encryption redesign plan / migration stages |
| `docs/samples/fake-sensor-payload.json` | Sample manufacturing JSON for Simulate → Payload |
| `docs/plan-activities-kafka-followups.md` | Deferred Activities / Kafka metrics work |
| `deploy/templates/prometheus.yml` | Scrape template for the agent `/metrics` job |
