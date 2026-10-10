# IoT Gateway Monitor

Cross-platform desktop app for the IoT gateway: **download → double-click → Setup Wizard → Monitoring + Actions**. No Python, Rust, or CLI setup for normal use.

| Piece | Role |
|-------|------|
| **Desktop app** (Windows `.exe` / Linux AppImage) | Setup Wizard, Monitoring, Actions, Lab, Admin |
| **Control service** (bundled inside the app) | SSH provision/register playbooks, local SQLite registry |
| **Gateway** (on Ubuntu / Raspberry Pi) | Mosquitto, HAProxy, **Node-RED (mandatory)**, IDS, exporters |
| **Observability** | App-managed Loki + Prometheus (Grafana optional) |

---

## Download & run (recommended)

Installers are published on the [**GitHub Releases**](https://github.com/ngmibach/iot-gateway/releases) page (built by GitHub Actions).

| Platform | File | How to run |
|----------|------|------------|
| **Windows 10/11** | `IoTGatewayMonitor.exe` | Download → double-click |
| **Ubuntu / Linux** | `IoTGatewayMonitor-x86_64.AppImage` | Download → allow execute once → double-click |

### Windows

1. Open the latest Release and download **`IoTGatewayMonitor.exe`**.
2. Double-click it. If SmartScreen appears: **More info → Run anyway**.
3. The app window opens (Setup Wizard). Use the UI for discover → SSH → install gateway → Register Device → Monitoring.

### Ubuntu / Linux

1. Download **`IoTGatewayMonitor-x86_64.AppImage`**.
2. Right-click → Properties → allow executing as program  
   *(or once in a terminal: `chmod +x IoTGatewayMonitor-x86_64.AppImage`)*
3. Double-click the AppImage. The app window opens.

All day-to-day work (provision, register device, cert download, monitoring, lab sensors, admin PIN / code signing) is done **in the UI**.

App data:

- Linux: `~/.local/share/iot-gateway-monitor/`
- Windows: `%APPDATA%\IoTGatewayMonitor\`

---

## What the app does

1. **Setup Wizard** — enter the gateway LAN IP, SSH as the device user, provision the Docker gateway stack.
2. **Actions → Register Device** — ACL + Mosquitto password + HAProxy allow-list + mTLS client cert (one-time download).
3. **Monitoring** — sensors / gateway / Raspberry Pi views against Loki + Prometheus.
4. **Lab** — short-lived fake sensors for demos.
5. **Admin → Code Signing** — sign release binaries locally via OS keyring (optional).

Node-RED stays mandatory on the gateway (decrypt → `sensor_data.log` for IDS/dashboards).

---

## Branches (only three)

| Branch | Role |
|--------|------|
| **`main`** | Integration branch + CI workflow definition (source of truth) |
| **`linux`** | Push here → CI builds `IoTGatewayMonitor-x86_64.AppImage` → [Releases](https://github.com/ngmibach/iot-gateway/releases) |
| **`windows`** | Push here → CI builds `IoTGatewayMonitor.exe` → [Releases](https://github.com/ngmibach/iot-gateway/releases) |

Workflow: [`.github/workflows/desktop-packages.yml`](.github/workflows/desktop-packages.yml) (GitHub-hosted runners). Successful builds update the **`desktop-latest`** release (same file names are replaced).

```shell
# Rebuild Linux package
git checkout linux
git merge main          # pick up shared changes when needed
git push origin linux   # → AppImage CI

# Rebuild Windows package
git checkout windows
git merge main
git push origin windows # → .exe CI
```

Manual rebuild: Actions → *Desktop packages* → Run workflow (choose linux / windows / both).

Local rebuild (developers only):

```shell
bash apps/desktop/packaging/build_linux_appimage.sh   # → AppImage
bash apps/desktop/packaging/build_windows.sh          # → .exe (on Windows / CI)
```

---

## Windows networking notes

- UI ports `:9137` / `:9138` use Windows **`localhostForwarding`** when services run inside WSL2 (`.wslconfig`). The downloadable `.exe` runs natively on Windows and binds localhost directly.
- Loki `:3100` firewall/portproxy steps appear as a **copyable checklist in the Setup Wizard** — the app never silently changes firewall rules.

---

## Advanced / legacy: Docker Compose lab

Power users can still run the classic three-folder stacks by hand. Prefer the downloadable app for new installs.

```shell
cd gateway && docker compose build && docker compose up -d
cd ../monitoring && docker compose build && docker compose up -d
# Optional lab traffic:
cd ../fake_sensor && docker compose build && docker compose up -d
```

| Service | URL |
|---------|-----|
| Grafana | http://localhost:3210 (`admin` / `admin`) |
| Prometheus | http://localhost:9090 |
| Loki | http://localhost:3100 |

Gitea + runner remain only under Compose profile `legacy-gitea` (deprecated control plane).

---

## Developer source run (optional)

Only needed if you are changing the app itself. End users should use Releases.

See [`apps/desktop/README.md`](apps/desktop/README.md) for venv / shortcut details.

```shell
cd apps/control-service && PYTHONPATH=. python -m unittest discover -s tests -v
```

---

## Repository layout

```
apps/desktop/           # Clickable app (shell + UI + packaging/)
apps/control-service/   # FastAPI, SSH actions, registry, telemetry
gateway/                # Device compose stack (Node-RED mandatory)
monitoring/             # Lab compose (Loki/Prom/Grafana)
deploy/templates/       # IP-templated Promtail/Prometheus snippets
.github/workflows/      # Builds .exe + AppImage → Releases
```
