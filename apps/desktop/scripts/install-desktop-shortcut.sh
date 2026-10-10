#!/usr/bin/env bash
# Install a double-clickable desktop + app-menu shortcut on Ubuntu/Linux.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
DESKTOP_APP="$ROOT/apps/desktop"
RUN="$DESKTOP_APP/scripts/run-app.sh"
ICON_SRC="$DESKTOP_APP/src-tauri/icons/icon.png"
chmod +x "$RUN" "$DESKTOP_APP/scripts/fetch-chrome-libs.sh" || true

# Ensure venv + Chromium for the app window (first-time setup).
if [[ ! -x "$DESKTOP_APP/.venv/bin/python" ]]; then
  echo "Creating Python venv…"
  if command -v uv >/dev/null 2>&1; then
    uv venv "$DESKTOP_APP/.venv"
    uv pip install --python "$DESKTOP_APP/.venv/bin/python" \
      -r "$DESKTOP_APP/requirements.txt" \
      -r "$ROOT/apps/control-service/requirements.txt" \
      playwright
  else
    python3 -m venv "$DESKTOP_APP/.venv"
    "$DESKTOP_APP/.venv/bin/pip" install -r "$DESKTOP_APP/requirements.txt" \
      -r "$ROOT/apps/control-service/requirements.txt" playwright
  fi
fi
"$DESKTOP_APP/.venv/bin/playwright" install chromium || true
"$DESKTOP_APP/scripts/fetch-chrome-libs.sh" || true

ICON_DST="$HOME/.local/share/icons/iot-gateway-monitor.png"
mkdir -p "$(dirname "$ICON_DST")"
cp -f "$ICON_SRC" "$ICON_DST"

APP_DIR="$HOME/.local/share/applications"
DESKTOP_DIR="${XDG_DESKTOP_DIR:-$HOME/Desktop}"
mkdir -p "$APP_DIR"
[[ -d "$DESKTOP_DIR" ]] || DESKTOP_DIR="$HOME/Desktop"
mkdir -p "$DESKTOP_DIR"

ENTRY_NAME="iot-gateway-monitor.desktop"
write_entry() {
  local dest="$1"
  cat >"$dest" <<EOF
[Desktop Entry]
Version=1.0
Type=Application
Name=IoT Gateway Monitor
Comment=Discover, install, and monitor IoT gateways
Exec=$RUN
Icon=$ICON_DST
Terminal=false
Categories=Network;System;Monitor;
StartupNotify=true
EOF
  chmod +x "$dest"
}

write_entry "$APP_DIR/$ENTRY_NAME"
write_entry "$DESKTOP_DIR/$ENTRY_NAME"

# Mark trusted on GNOME so double-click works without "Untrusted" dialog.
if command -v gio >/dev/null 2>&1; then
  gio set "$DESKTOP_DIR/$ENTRY_NAME" metadata::trusted true 2>/dev/null || true
fi
update-desktop-database "$APP_DIR" 2>/dev/null || true

echo "Installed:"
echo "  App menu: $APP_DIR/$ENTRY_NAME"
echo "  Desktop:  $DESKTOP_DIR/$ENTRY_NAME"
echo "Double-click “IoT Gateway Monitor” to open the app window."
