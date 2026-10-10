# IoT Gateway Monitor — desktop app (Phase-0/1)

**Double-clickable application** (Ubuntu + Windows): opens a real app window with Setup Wizard, Actions, native Monitoring, Lab, and Admin Code Signing. You do **not** need to run CLI commands for normal use.

## Install & open (Ubuntu — recommended right now)

From the repo:

```bash
apps/desktop/scripts/install-desktop-shortcut.sh
```

That creates **IoT Gateway Monitor** on your Desktop and in the app menu. Double-click it.

What the shortcut does:

1. Starts the local control API (`:9137`) and wizard server (`:9138`)
2. Opens an app window (Chromium `--app=` mode — no address bar)
3. Quits services when you close the window

First run may download Chromium (Playwright) and extract a few Chrome runtime `.deb` libs into `apps/desktop/.local-libs/` (no `sudo`).

Manual launch (same as the shortcut):

```bash
apps/desktop/scripts/run-app.sh
```

## Windows / Ubuntu installers (Tauri)

CI builds installers via `.github/workflows/desktop-packages.yml`:

| OS | Artifact |
|----|----------|
| Ubuntu | `.AppImage` — chmod +x and double-click |
| Windows | `.msi` / NSIS `.exe` — Start Menu + Desktop shortcut |

Local Tauri build (needs Rust + WebKitGTK on Linux, WebView2 on Windows):

```bash
cargo install tauri-cli --version "^2"
cd apps/desktop
cargo tauri build
# → src-tauri/target/release/bundle/appimage|msi|nsis/
```

On launch, Tauri starts `python -m shell --start-services`, shows `splash.html`, then navigates to the wizard. Sign release binaries via **Admin → Code Signing**.

## What ships

| Piece | Role |
|-------|------|
| `shell/` | Desktop backend: Docker/WSL detect, NIC, SSH pin, firewall checklist, launcher, Admin PIN, **`--gui` app window** |
| `ui/` | Setup Wizard + Actions + Monitoring + Lab + Admin |
| `src-tauri/` | Tauri 2 — AppImage / MSI / NSIS packaging |
| `scripts/run-app.sh` | Double-click entrypoint |
| `scripts/install-desktop-shortcut.sh` | Installs Desktop + app-menu shortcut |

**Windows networking**

- UI ports `:9137` / `:8501` → Windows **`localhostForwarding`** only (`.wslconfig`). **No** `netsh portproxy` for these.
- Loki `:3100` → Setup Wizard shows copyable `netsh` portproxy + firewall commands; user runs elevated and confirms. App never auto-applies firewall rules.

## CLI / developer mode

```bash
# From repo root
python3 -m venv apps/desktop/.venv
apps/desktop/.venv/bin/pip install -r apps/desktop/requirements.txt \
  -r apps/control-service/requirements.txt

export PYTHONPATH=apps/desktop:apps/control-service
apps/desktop/.venv/bin/python -m shell --gui          # app window
apps/desktop/.venv/bin/python -m shell --detect-only
IOTGW_FORCE_CLI=1 apps/desktop/.venv/bin/python -m shell --no-browser
```

Smoke:

```bash
apps/desktop/scripts/smoke.sh
```

## Admin Code Signing (K16)

1. Open `http://127.0.0.1:9138/admin.html` (or Wizard → Admin).
2. Set/unlock local admin PIN (OS keyring).
3. Load `.pfx` / GPG identity (passphrases → keyring; never audit_log).
4. Scan build folder or paste `.msi`/`.exe`/`.AppImage`/`.deb` paths → Sign.
5. Export folder includes signed artifacts + `SHA256SUMS`.

Requires `osslsigncode` or `signtool` (Windows) and/or `gpg` (Ubuntu) on PATH.

### Windows localhostForwarding

If the WebView cannot reach `http://127.0.0.1:9137` / `:8501` while services run inside WSL2, set in `%UserProfile%\.wslconfig`:

```ini
[wsl2]
localhostForwarding=true
```

Then `wsl --shutdown` and relaunch. Do **not** fall back to portproxy for UI ports.

## Layout

```
apps/desktop/
  README.md
  requirements.txt
  shell/           # python -m shell
  ui/              # wizard.html + assets
  src-tauri/       # Tauri 2
  tests/
  scripts/smoke.sh
```

App data: Linux `~/.local/share/iot-gateway-monitor/`, Windows `%APPDATA%\IoTGatewayMonitor\` (`settings.json`, `known_hosts`, `ssh/`, keyring fallback file if no OS backend).
