#!/bin/bash
set -e

# Ensure logs directory exists
mkdir -p /data/logs
mkdir -p /app/nodered_logs

# Start IDS model in background with output capture
echo "[ENTRYPOINT] Starting IDS model..."
python -u -m ids_gateway.main /app/configs/ids_config.yaml >> /data/logs/ids_runtime.log 2>&1 &
IDS_PID=$!
echo "[ENTRYPOINT] IDS model started with PID $IDS_PID"

# Trap signals to cleanup
cleanup() {
    echo "[ENTRYPOINT] Cleaning up..."
    kill $IDS_PID 2>/dev/null || true
    wait $IDS_PID 2>/dev/null || true
}
trap cleanup EXIT TERM INT

# Start Node-RED in foreground
echo "[ENTRYPOINT] Starting Node-RED..."
exec node-red --userDir /data
