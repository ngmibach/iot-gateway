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
# Absolute path so subshells (cd control-service) still find the interpreter.
if [[ "$PY" == */* ]]; then
  PY="$(cd "$(dirname "$PY")" && pwd)/$(basename "$PY")"
else
  PY="$(command -v "$PY")"
fi
export PYTHONPATH="$DESKTOP:$CS${PYTHONPATH:+:$PYTHONPATH}"
export IOTGW_DATA_DIR="${IOTGW_DATA_DIR:-$(mktemp -d /tmp/iotgw-desktop-smoke.XXXXXX)}"

echo "== unit tests (desktop) =="
"$PY" -m unittest discover -s "$DESKTOP/tests" -v

echo "== unit tests (signing) =="
"$PY" -m unittest discover -s "$CS/signing" -v

echo "== detect-only =="
"$PY" -m shell --detect-only | head -c 2000
echo

echo "== wizard + admin server brief =="
"$PY" - <<'PY'
import json, threading, time, urllib.request
from shell.wizard_server import serve
srv = serve("127.0.0.1", 0, open_browser=False)
port = srv.server_address[1]
t = threading.Thread(target=srv.serve_forever, daemon=True)
t.start()
time.sleep(0.2)
base = f"http://127.0.0.1:{port}"
with urllib.request.urlopen(base + "/api/wizard/env", timeout=5) as r:
    data = json.loads(r.read().decode())
assert "docker" in data
with urllib.request.urlopen(f"http://127.0.0.1:{port}/actions.html", timeout=5) as r:
    html = r.read().decode()
assert "Rotate server" in html and "Unregister" in html
ctrl = json.loads(urllib.request.urlopen(f"http://127.0.0.1:{port}/api/wizard/control", timeout=5).read())
assert ctrl.get("url")
with urllib.request.urlopen(base + "/admin.html", timeout=5) as r:
    assert b"Code Signing" in r.read()
with urllib.request.urlopen(base + "/api/admin/status", timeout=5) as r:
    st = json.loads(r.read().decode())
assert "has_pin" in st
print("wizard+actions+admin ok on", port, "docker.present=", data["docker"]["present"])
srv.shutdown()
PY

echo "== control-service API + rotate unit =="
(
  cd "$CS"
  export PYTHONPATH="$CS${PYTHONPATH:+:$PYTHONPATH}"
  "$PY" -m unittest discover -s tests -p 'test_api.py' -v
  "$PY" -m unittest discover -s tests -p 'test_rotate_certs.py' -v
)

echo "SMOKE OK"
