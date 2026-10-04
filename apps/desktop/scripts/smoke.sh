#!/usr/bin/env bash
# Phase-0 desktop smoke: unit tests + detect-only + wizard HTTP ping.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
DESKTOP="$ROOT/apps/desktop"
CS="$ROOT/apps/control-service"
PY="${PYTHON:-}"
if [[ -z "$PY" ]]; then
  if [[ -x "$DESKTOP/.venv/bin/python" ]]; then
    PY="$DESKTOP/.venv/bin/python"
  else
    PY=python3
  fi
fi
export PYTHONPATH="$DESKTOP:$CS${PYTHONPATH:+:$PYTHONPATH}"
export IOTGW_DATA_DIR="${IOTGW_DATA_DIR:-$(mktemp -d /tmp/iotgw-desktop-smoke.XXXXXX)}"

echo "== unit tests =="
"$PY" -m unittest discover -s "$DESKTOP/tests" -v

echo "== detect-only =="
"$PY" -m shell --detect-only | head -c 2000
echo

echo "== wizard server brief =="
"$PY" - <<'PY'
import json, threading, time, urllib.request
from shell.wizard_server import serve
srv = serve("127.0.0.1", 0, open_browser=False)
port = srv.server_address[1]
t = threading.Thread(target=srv.serve_forever, daemon=True)
t.start()
time.sleep(0.2)
url = f"http://127.0.0.1:{port}/api/wizard/env"
with urllib.request.urlopen(url, timeout=5) as r:
    data = json.loads(r.read().decode())
assert "docker" in data
print("wizard ok on", port, "docker.present=", data["docker"]["present"])
srv.shutdown()
PY

echo "SMOKE OK"
