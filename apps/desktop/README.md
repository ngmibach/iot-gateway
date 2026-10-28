# IoT Gateway Monitor — desktop app

Packaged Windows `.exe` / Linux AppImage for the monitoring UI and wizard shell.

**Operators:** download and run from the root [`README.md`](../../README.md). Feature and tab guide: [`docs/UI.md`](../../docs/UI.md).

**Maintainers**

- Push `linux` → AppImage; push `windows` → `.exe` (workflow on `main`).
- Local: `bash apps/desktop/packaging/build_linux_appimage.sh` / `build_windows.sh`.

```
apps/desktop/
  packaging/   # PyInstaller + AppImage/exe
  shell/       # wizard server + GUI
  ui/          # wizard / gateways / monitoring / actions / settings / certificates / admin
```
)
