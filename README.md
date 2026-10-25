# IoT Gateway Monitor

Cross-platform desktop app: **download → double-click → Setup Wizard → provision gateway agent → Monitoring + Actions**.

No Docker on the operator PC. No WSL required on Windows. No Docker on the gateway.

| Piece | Role |
|-------|------|
| **Desktop app** (Windows `.exe` / Linux AppImage) | Wizard, Actions, Monitoring, Admin |
| **Local Loki + Prometheus** | App-managed native processes (downloaded once in-UI) |
| **Gateway agent** | One systemd service: Mosquitto (native) + decrypt → log + metrics + Loki shipper + mDNS |
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

## Architecture

```
Operator PC                         Gateway device
─────────────                       ──────────────
IoTGatewayMonitor                   iot-gateway-agent (systemd)
  Wizard / Actions / Monitoring       ├─ mosquitto (native apt, systemd)
  Loki :3100 (native process)         ├─ decrypt → sensor_data.log
  Prometheus :9090 (native)           ├─ Loki shipper → MONITORING_IP:3100
                                      ├─ GET :9139/metrics /v1/health
                                      └─ mDNS
```

Sensor Registration updates Mosquitto ACL + password file under
`/var/lib/iot-gateway-agent/mosquitto/` and reloads system Mosquitto. Optional
mTLS client certs are still issued from the gateway CA for download to devices.

Publish test traffic with any MQTT client to the gateway on port 1883.

---

## Repository layout

| Path | Purpose |
|------|---------|
| `apps/desktop/` | Packaged UI, wizard shell, Windows/Linux packaging |
| `apps/control-service/` | FastAPI control plane, provisioner, telemetry, actions |
| `gateway/agent/` | Monolithic gateway agent (systemd unit + Python package) |
| `deploy/templates/prometheus.yml` | Scrape template for the agent `/metrics` job |
