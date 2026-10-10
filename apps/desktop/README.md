# IoT Gateway Monitor — desktop app

**Double-clickable** Windows `.exe` / Linux AppImage. Setup Wizard, Actions, Monitoring, Admin — **no Docker on this PC**, no Lab panel in this build.

## End users

Download from [Releases / desktop-latest](https://github.com/ngmibach/iot-gateway/releases/tag/desktop-latest).

1. **Prepare monitoring** in the Wizard (app fetches Loki + Prometheus).
2. SSH pin + key → **Install / update gateway agent** (native Mosquitto + monolithic agent on the device).
3. Actions + Monitoring in the UI.

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
