# IoT Gateway Monitor

Cross-platform desktop app: **download → double-click → Setup Wizard → provision gateway agent → Monitoring + Actions**.

No Docker on the operator PC. No Docker on the gateway. No Lab / fake-sensor panel in this build.

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
| **Windows** | `IoTGatewayMonitor.exe` | Download → double-click |
| **Ubuntu / Linux** | `IoTGatewayMonitor-x86_64.AppImage` | `chmod +x` once → double-click |

### First-run Wizard (all in the UI)

1. **Local monitoring** — click **Prepare monitoring**. The app downloads Loki + Prometheus once and starts them (no browser, no Docker).
2. **NIC** — pick MONITORING_IP (LAN address the gateway will push logs to).
3. **SSH** — pin host key, install ed25519 key (one-time password).
4. **Firewall** (Windows) — optional guided checklist for Loki `:3100`.
5. **Launch** — start control service, enter the **gateway sudo password**, then **Install / update gateway agent** (apt packages + agent over SSH via `sudo -S`; password is not saved on the PC; no Docker on the device).

Then use **Actions** (register devices / certs) and **Monitoring**.

App data: Linux `~/.local/share/iot-gateway-monitor/`, Windows `%APPDATA%\IoTGatewayMonitor\`.

---

## Branches

| Branch | Role |
|--------|------|
| **`main`** | Integration + CI workflow |
| **`linux`** | Push → rebuild AppImage → `desktop-latest` |
| **`windows`** | Push → rebuild `.exe` → `desktop-latest` |

---

## Architecture (Docker-free)

```
Operator PC                         Gateway device
─────────────                       ──────────────
IoTGatewayMonitor                   iot-gateway-agent (systemd)
  Wizard / Actions / Monitoring       ├─ mosquitto (native apt, supervised)
  Loki :3100 (native process)         ├─ decrypt → sensor_data.log
  Prometheus :9090 (native)           ├─ Loki shipper → MONITORING_IP:3100
                                      ├─ GET :9139/metrics /v1/health
                                      └─ mDNS
```

Legacy `gateway/docker-compose.yaml` remains for power users only (`IOTGW_GATEWAY_BACKEND=compose`). The default Wizard path never asks for Docker.

---

## Advanced / legacy Compose lab

```shell
cd gateway && docker compose up -d   # optional; not required for the packaged app
```

Fake sensors are not part of the packaged UI; publish with any MQTT client to the agent on port 1883.
