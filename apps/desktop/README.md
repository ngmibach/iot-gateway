# IoT Gateway Monitor — desktop app

**Double-clickable** Windows `.exe` / Linux AppImage. First launch opens the Setup Wizard only; after install the app opens a left-rail shell (**Monitoring** + **Settings**) — **no Docker and no WSL on the Windows PC**, no Lab panel in this build.

## End users

Download from [Releases / desktop-latest](https://github.com/ngmibach/iot-gateway/releases/tag/desktop-latest).

| Platform | File | First run |
|----------|------|-----------|
| Windows | `IoTGatewayMonitor.exe` | Double-click. **WSL is not required.** Loki and Prometheus run as native Windows processes under `%APPDATA%\\IoTGatewayMonitor`. If SmartScreen says unrecognized: **More info → Run anyway**. |
| Linux | `IoTGatewayMonitor-*.AppImage` | `chmod +x` once, then double-click. |

1. First launch: Setup Wizard only (no Monitoring / Control Plane / Admin links yet).
2. Choose **Monitoring only** (default) or **Full setup**.
3. Click **Install monitoring** — the app downloads Loki + Prometheus and starts them (progress is polled; no Docker).
4. Click **Open Monitoring** (or Finish → Done). The next launch skips the installer and opens the app shell:
   - **Monitoring:** Gateway Metric · Gateway Activities · Control Plane
   - **Settings:** Setup · Remove · Admin
5. Gateway SSH/agent steps stay optional until you pick Full setup.
6. **Settings → Remove:** Gateway only (keeps Loki/Prometheus), or Monitoring panel (also removes every gateway registered to that panel and wipes local app data). Returns you to the first-run wizard after a Monitoring wipe.

## Maintainers

- Push `linux` → AppImage; push `windows` → `.exe` (workflow on `main`).
- Local: `bash apps/desktop/packaging/build_linux_appimage.sh` / `build_windows.sh`.

## Layout

```
apps/desktop/
  packaging/   # PyInstaller + AppImage/exe
  shell/       # wizard server + GUI
  ui/          # wizard / actions / monitoring / admin
```
