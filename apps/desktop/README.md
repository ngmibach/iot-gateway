# IoT Gateway Monitor — desktop app

**Double-clickable application** (Windows + Ubuntu): opens a real app window with Setup Wizard, Actions, Monitoring, Lab, and Admin. Normal use needs **no CLI**.

---

## End users — download & run

Get installers from the project [**GitHub Releases**](https://github.com/ngmibach/iot-gateway/releases):

| OS | Download | Run |
|----|----------|-----|
| Windows | `IoTGatewayMonitor.exe` | Double-click |
| Ubuntu / Linux | `IoTGatewayMonitor-x86_64.AppImage` | `chmod +x` once → double-click |

Everything else (SSH provision, Register Device, certs, monitoring, lab, admin PIN) is done in the **UI**.

Built by [`.github/workflows/desktop-packages.yml`](../../.github/workflows/desktop-packages.yml) on GitHub-hosted runners (`windows-latest` + `ubuntu-24.04`).

---

## What ships in the package

| Piece | Role |
|-------|------|
| Bundled Python runtime | No system Python required |
| `shell/` + `ui/` | App window, Setup Wizard, Actions, Monitoring, Lab, Admin |
| `control-service/` | Local API on `127.0.0.1:9137` |
| `gateway/` + `deploy/` + `tools/` | Provisioner upload bundle + templates |

On launch the app starts the control API, serves the wizard on `:9138`, and opens a Chromium/Edge **app window** (no address bar). Closing the window stops the services.

App data: Linux `~/.local/share/iot-gateway-monitor/`, Windows `%APPDATA%\IoTGatewayMonitor\`.

---

## Maintainers — CI & local package builds

```shell
# Linux AppImage → apps/desktop/dist/IoTGatewayMonitor-x86_64.AppImage
bash apps/desktop/packaging/build_linux_appimage.sh

# Windows .exe → apps/desktop/dist/IoTGatewayMonitor.exe  (run on Windows / CI)
bash apps/desktop/packaging/build_windows.sh
```

Publish: push a `desktop-v*` / `v*` tag, or Actions → *Desktop packages* → Run workflow with **publish_release**.

Sign release binaries from **Admin → Code Signing** inside the running app (keyring; not CI-only secrets).

---

## Developers — source tree (optional)

Only for changing the app. Prefer Releases for daily use.

```bash
# One-time shortcut on Ubuntu (uses repo venv + Playwright Chrome if needed)
apps/desktop/scripts/install-desktop-shortcut.sh
# or:
apps/desktop/scripts/run-app.sh
```

```bash
python3 -m venv apps/desktop/.venv
apps/desktop/.venv/bin/pip install -r apps/desktop/requirements.txt \
  -r apps/control-service/requirements.txt
export PYTHONPATH=apps/desktop:apps/control-service
apps/desktop/.venv/bin/python -m shell --gui
```

Smoke: `apps/desktop/scripts/smoke.sh`

### Windows networking (WSL2 labs)

- Downloadable `.exe` binds localhost on Windows directly.
- If you run services inside WSL2 and open a WebView on Windows, set `%UserProfile%\.wslconfig`:

```ini
[wsl2]
localhostForwarding=true
```

Then `wsl --shutdown` and relaunch. Loki `:3100` still uses the Setup Wizard’s copyable `netsh` checklist (app never auto-applies firewall rules).

---

## Layout

```
apps/desktop/
  README.md
  packaging/          # PyInstaller spec + AppImage/exe build scripts
  shell/              # python -m shell / frozen entry
  ui/                 # wizard + actions + monitoring + lab + admin
  scripts/            # local shortcut / smoke (developers)
  src-tauri/          # optional Tauri path (icons reused)
  tests/
```
