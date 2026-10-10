#!/usr/bin/env bash
# Build a double-clickable Windows IoTGatewayMonitor.exe (PyInstaller onefile).
# Intended for GitHub Actions windows-latest; can also run under native Windows bash.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
DESKTOP="$ROOT/apps/desktop"
PACK="$DESKTOP/packaging"
OUT="${IOTGW_DIST:-$DESKTOP/dist}"

cd "$ROOT"
python -m pip install -U pip wheel
python -m pip install pyinstaller \
  -r "$DESKTOP/requirements.txt" \
  -r "$ROOT/apps/control-service/requirements.txt"

export IOTGW_PYI_ONEFILE=1
export IOTGW_PYI_CONSOLE="${IOTGW_PYI_CONSOLE:-0}"

python -m PyInstaller \
  --noconfirm \
  --clean \
  --distpath "$OUT" \
  --workpath "$DESKTOP/build/pyinstaller" \
  "$PACK/iot-gateway-monitor.spec"

EXE="$OUT/IoTGatewayMonitor.exe"
if [[ ! -f "$EXE" ]]; then
  echo "ERROR: expected $EXE" >&2
  ls -la "$OUT" >&2 || true
  exit 1
fi

# Checksums next to the artifact
(
  cd "$OUT"
  if command -v sha256sum >/dev/null; then
    sha256sum IoTGatewayMonitor.exe > SHA256SUMS-windows.txt
  elif command -v shasum >/dev/null; then
    shasum -a 256 IoTGatewayMonitor.exe > SHA256SUMS-windows.txt
  fi
)

echo "Built: $EXE"
ls -lh "$EXE"
