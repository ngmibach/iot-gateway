# IoT Gateway Monitor — desktop (Phase-0/1)

Setup Wizard + Actions chrome + process launcher for the Python control service (`127.0.0.1:9137`) and **native Monitoring** UI (`/monitoring.html`). Streamlit (`127.0.0.1:8501`) remains optional. Tauri 2 hosts the wizard/Actions and can WebView-navigate to Monitoring.

## What ships

| Piece | Role |
|-------|------|
| `shell/` | Working Python shell: Docker/WSL detect, NIC pick, SSH host-key pin + ed25519 install, **guided** Windows firewall/portproxy checklist (K18 — display only), OS keyring refs, start/stop API (+ optional Streamlit), Admin PIN |
| `ui/` | Setup Wizard + **Actions** + native Monitoring + Lab (`lab.html`) + **Admin / Code Signing** |

| `shell/` | Working Python shell: Docker/WSL detect, NIC pick, SSH host-key pin + ed25519 install, **guided** Windows firewall/portproxy checklist (K18 — display only), OS keyring refs, start/stop API + Streamlit, **admin unlock** |
| `ui/` | Setup Wizard + **Admin / Code Signing** pages (also Tauri `frontendDist`) |
| `src-tauri/` | Tauri 2 scaffold — Linux AppImage / Windows MSI·NSIS packaging stubs |

**Windows networking**

- UI ports `:9137` / `:8501` → Windows **`localhostForwarding`** only (`.wslconfig`). **No** `netsh portproxy` for these.
- Loki `:3100` → Setup Wizard shows copyable `netsh` portproxy + firewall commands; user runs elevated and confirms. App never auto-applies firewall rules.

## Quick start (Python shell — no Rust required)

```bash
# From repo root
python3 -m venv apps/desktop/.venv
apps/desktop/.venv/bin/pip install -r apps/desktop/requirements.txt \
  -r apps/control-service/requirements.txt
# Optional Streamlit embed:
# apps/desktop/.venv/bin/pip install -r monitoring/build/streamlit/requirements.txt

export PYTHONPATH=apps/desktop:apps/control-service
export IOTGW_DATA_DIR="${IOTGW_DATA_DIR:-$HOME/.local/share/iot-gateway-monitor}"

# Detection only
apps/desktop/.venv/bin/python -m shell --detect-only

# Wizard UI on http://127.0.0.1:9138/wizard.html
# Actions  on http://127.0.0.1:9138/actions.html  (calls FastAPI :9137)
apps/desktop/.venv/bin/python -m shell --no-browser
# Start control API (native Monitoring is default; add --with-streamlit if needed):
apps/desktop/.venv/bin/python -m shell --start-services --no-browser
# Monitoring MUST be loaded from the wizard origin (same-origin /api/v1 proxy + token):
#   http://127.0.0.1:9138/monitoring.html
# Do not open ui/monitoring.html from Tauri frontendDist / file:// — those skip the proxy.
```

Smoke:

```bash
apps/desktop/scripts/smoke.sh
```

## Tauri build (`cargo tauri build`)

Prereqs: Rust stable, Node (for `@tauri-apps/cli` optional), platform WebView (WebKitGTK on Linux, WebView2 on Windows).

```bash
# Install CLI once
cargo install tauri-cli --version "^2"

cd apps/desktop
# Dev: starts Python wizard (beforeDevCommand) + Tauri window on ui/
cargo tauri dev

# Release bundles: AppImage (Linux), MSI/NSIS (Windows)
cargo tauri build
# Artifacts under src-tauri/target/release/bundle/
```

`tauri.conf.json` bundle targets: `appimage`, `msi`, `nsis`. Replace `src-tauri/icons/icon.png` with brand assets before shipping; sign outputs via **Admin → Code Signing** (see `apps/control-service/signing/README.md`).

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
