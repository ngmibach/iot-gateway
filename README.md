# IoT Gateway Monitor

Cross-platform desktop app to install a local monitoring stack, provision gateway agents over SSH, register sensors, and watch metrics and message activity.

No Docker on the operator PC. No WSL required on Windows. No Docker on the gateway.

| Piece | Role |
|-------|------|
| **Desktop app** (Windows `.exe` / Linux AppImage) | Wizard, Gateways, Monitoring, Control Plane, Settings |
| **Local Loki + Prometheus + Grafana** | App-managed native processes (downloaded once in-UI) |
| **Gateway agent** | Systemd service: MQTTS ingress, decrypt, Kafka per sensor, metrics, Loki shipper |
| **Communication** | SSH for control/provision; MQTTS + HTTP for data |

---

## Download & run

[**GitHub Releases — desktop-latest**](https://github.com/ngmibach/iot-gateway/releases/tag/desktop-latest)

| Platform | File | How to run |
|----------|------|------------|
| **Windows** | `IoTGatewayMonitor.exe` | Download → double-click (WSL not required). CI Authenticode-signs when signing secrets are set; otherwise SmartScreen/Chrome may block unsigned PyInstaller builds (**More info → Run anyway**). |
| **Ubuntu / Linux** | `IoTGatewayMonitor-x86_64.AppImage` | `chmod +x` once → double-click |

### First run

1. **Install monitoring** — downloads Loki + Prometheus + Grafana once, then **Open app**.
2. **Gateways → Registration** — Find gateway (SSH), enter credentials, **Install gateway**.
3. Use **Monitoring** for Metric / Activities / Control Plane; open **Grafana** from the left nav when you need dashboards.

App data: Linux `~/.local/share/iot-gateway-monitor/`, Windows `%APPDATA%\IoTGatewayMonitor\`.

Full click-paths for every tab: [`docs/UI.md`](docs/UI.md).

---

## Branches

| Branch | Role |
|--------|------|
| **`main`** | Integration + CI workflow |
| **`linux`** | Push → rebuild AppImage → `desktop-latest` |
| **`windows`** | Push → rebuild `.exe` → `desktop-latest` |

Shared docs/UI changes ship on `windows` then `linux` (`docs(windows):` / `docs(linux):` or feat/fix pairs), then return to `windows`.

---

## Documentation

| Doc | Contents |
|-----|----------|
| [`docs/architecture.md`](docs/architecture.md) | Mermaid overview: system, monitoring app, gateway, data path, encryption, operations |
| [`docs/details.md`](docs/details.md) | Ports, paths, APIs, Kafka capacity, envelope v1 crypto, fake sensors |
| [`docs/UI.md`](docs/UI.md) | How to use Wizard and every Monitoring / Gateways / Settings feature |
| [`docs/samples/`](docs/samples/) | Sample payloads (for example Simulate manufacturing JSON) |

---

## Repository layout

| Path | Purpose |
|------|---------|
| `apps/desktop/` | Packaged UI, wizard shell, Windows/Linux packaging |
| `apps/control-service/` | FastAPI control plane, provisioner, telemetry, actions |
| `gateway/agent/` | Monolithic gateway agent (systemd unit + Python package) |
| `docs/` | Architecture, details, UI guide, samples |
| `deploy/templates/prometheus.yml` | Scrape template for the agent `/metrics` job |
)
