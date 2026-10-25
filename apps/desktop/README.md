# IoT Gateway Monitor — desktop app

**Double-clickable** Windows `.exe` / Linux AppImage. First launch opens the Setup Wizard only; after install the app opens a left-rail shell (**Monitoring** + **Gateways** + **Settings**) — **no Docker and no WSL on the Windows PC**.

## End users

Download from [Releases / desktop-latest](https://github.com/ngmibach/iot-gateway/releases/tag/desktop-latest).

| Platform | File | First run |
|----------|------|-----------|
| Windows | `IoTGatewayMonitor.exe` | Double-click. **WSL is not required.** Loki and Prometheus run as native Windows processes under `%APPDATA%\IoTGatewayMonitor`. If SmartScreen says unrecognized: **More info → Run anyway**. |
| Linux | `IoTGatewayMonitor-*.AppImage` | `chmod +x` once, then double-click. |

1. First launch: Setup Wizard — **Install monitoring**, then **Open app**.
2. App shell sections:
   - **Monitoring:** Gateway Metric · Gateway Activities · Control Plane
   - **Gateways:** Registration · Settings · Clean up
   - **Settings:** Remove (panel) · Admin
3. Register gateways under **Gateways → Registration**: Find gateway (SSH scan), select a host, Install gateway. Configure under **Gateways → Settings**. Remove one gateway under **Gateways → Clean up**.
4. **Settings → Remove** uninstalls the monitoring panel on this PC (and every gateway registered to it). Returns you to the first-run wizard.

## Maintainers

- Push `linux` → AppImage; push `windows` → `.exe` (workflow on `main`).
- Local: `bash apps/desktop/packaging/build_linux_appimage.sh` / `build_windows.sh`.

## Layout

```
apps/desktop/
  packaging/   # PyInstaller + AppImage/exe
  shell/       # wizard server + GUI
  ui/          # wizard / gateways / monitoring / actions / settings / admin
```
