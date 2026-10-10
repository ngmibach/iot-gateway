#!/usr/bin/env bash
# Double-click / .desktop entrypoint — opens IoT Gateway Monitor as an app window.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
DESKTOP="$ROOT/apps/desktop"
CS="$ROOT/apps/control-service"

if [[ -x "$DESKTOP/.venv/bin/python" ]]; then
  PY="$DESKTOP/.venv/bin/python"
else
  PY="${PYTHON:-python3}"
fi

export PYTHONPATH="$DESKTOP:$CS${PYTHONPATH:+:$PYTHONPATH}"
export IOTGW_DATA_DIR="${IOTGW_DATA_DIR:-$HOME/.local/share/iot-gateway-monitor}"

# Optional Chrome runtime libs extracted without sudo (see fetch-chrome-libs.sh).
LIBROOT="$DESKTOP/.local-libs/usr/lib/x86_64-linux-gnu"
if [[ -d "$LIBROOT" ]]; then
  export LD_LIBRARY_PATH="$LIBROOT${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
fi

cd "$ROOT"
exec "$PY" -m shell --gui "$@"
