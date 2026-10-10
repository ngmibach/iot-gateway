#!/usr/bin/env bash
# Build a double-clickable IoTGatewayMonitor-x86_64.AppImage (PyInstaller onedir + appimagetool).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
DESKTOP="$ROOT/apps/desktop"
PACK="$DESKTOP/packaging"
OUT="${IOTGW_DIST:-$DESKTOP/dist}"
APPDIR="$OUT/IoTGatewayMonitor.AppDir"
ARCH="${IOTGW_ARCH:-x86_64}"

cd "$ROOT"
python3 -m pip install -U pip wheel
python3 -m pip install pyinstaller \
  -r "$DESKTOP/requirements.txt" \
  -r "$ROOT/apps/control-service/requirements.txt"

export IOTGW_PYI_ONEFILE=0
export IOTGW_PYI_CONSOLE="${IOTGW_PYI_CONSOLE:-0}"

python3 -m PyInstaller \
  --noconfirm \
  --clean \
  --distpath "$OUT" \
  --workpath "$DESKTOP/build/pyinstaller" \
  "$PACK/iot-gateway-monitor.spec"

BIN_DIR="$OUT/IoTGatewayMonitor"
if [[ ! -x "$BIN_DIR/IoTGatewayMonitor" ]]; then
  echo "ERROR: expected $BIN_DIR/IoTGatewayMonitor" >&2
  ls -la "$OUT" "$BIN_DIR" 2>&1 || true
  exit 1
fi

rm -rf "$APPDIR"
mkdir -p "$APPDIR/usr/bin" "$APPDIR/usr/share/applications" "$APPDIR/usr/share/icons/hicolor/256x256/apps"

# Payload: whole onedir next to a thin AppRun that execs the binary.
cp -a "$BIN_DIR" "$APPDIR/usr/lib/iot-gateway-monitor"
ln -sf ../lib/iot-gateway-monitor/IoTGatewayMonitor "$APPDIR/usr/bin/IoTGatewayMonitor"

ICON_SRC="$DESKTOP/src-tauri/icons/icon.png"
ICON_DST="$APPDIR/usr/share/icons/hicolor/256x256/apps/iot-gateway-monitor.png"
cp "$ICON_SRC" "$ICON_DST"
cp "$ICON_SRC" "$APPDIR/iot-gateway-monitor.png"

cat > "$APPDIR/iot-gateway-monitor.desktop" <<'EOF'
[Desktop Entry]
Type=Application
Name=IoT Gateway Monitor
Comment=Discover, provision, and monitor your IoT gateway
Exec=IoTGatewayMonitor
Icon=iot-gateway-monitor
Categories=Network;Utility;
Terminal=false
StartupNotify=true
EOF
cp "$APPDIR/iot-gateway-monitor.desktop" "$APPDIR/usr/share/applications/"

cat > "$APPDIR/AppRun" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
HERE="$(dirname "$(readlink -f "$0")")"
export APPDIR="${APPDIR:-$HERE}"
# Prefer bundled Chromium/system Chrome via the app itself; keep user libs available.
exec "$HERE/usr/lib/iot-gateway-monitor/IoTGatewayMonitor" "$@"
EOF
chmod +x "$APPDIR/AppRun"

# Fetch appimagetool (official continuous build).
TOOL_DIR="${IOTGW_APPIMAGETOOL_DIR:-$DESKTOP/build/appimagetool}"
mkdir -p "$TOOL_DIR"
TOOL="$TOOL_DIR/appimagetool-$ARCH.AppImage"
if [[ ! -x "$TOOL" ]]; then
  curl -fsSL -o "$TOOL" \
    "https://github.com/AppImage/appimagetool/releases/download/continuous/appimagetool-${ARCH}.AppImage"
  chmod +x "$TOOL"
fi

mkdir -p "$OUT"
APPIMAGE="$OUT/IoTGatewayMonitor-${ARCH}.AppImage"
# Extract appimagetool if FUSE is unavailable (common on CI).
if "$TOOL" --appimage-extract-and-run "$APPDIR" "$APPIMAGE" 2>/tmp/appimagetool.err; then
  :
elif APPIMAGE_EXTRACT_AND_RUN=1 "$TOOL" "$APPDIR" "$APPIMAGE" 2>>/tmp/appimagetool.err; then
  :
else
  # Last resort: manually extract and run
  (
    cd "$TOOL_DIR"
    rm -rf squashfs-root
    "$TOOL" --appimage-extract >/dev/null
    ./squashfs-root/AppRun "$APPDIR" "$APPIMAGE"
  )
fi

if [[ ! -f "$APPIMAGE" ]]; then
  echo "ERROR: AppImage not produced" >&2
  cat /tmp/appimagetool.err >&2 || true
  exit 1
fi
chmod +x "$APPIMAGE"

(
  cd "$OUT"
  sha256sum "IoTGatewayMonitor-${ARCH}.AppImage" > SHA256SUMS-linux.txt
)

echo "Built: $APPIMAGE"
ls -lh "$APPIMAGE"
