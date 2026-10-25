# Architecture (Docker-free)

## Operator PC

- Packaged app: `IoTGatewayMonitor.exe` (Windows) or AppImage (Linux).
- Local control service on `127.0.0.1:9137`; wizard/UI on `:9138`.
- Loki (`:3100`) and Prometheus (`:9090`) as native processes under the app data directory.
- Device registry in SQLite; secrets in the OS keyring (with file fallback).

## Gateway device

- `iot-gateway-agent` systemd unit under `/opt/iot-gateway-agent`.
- System Mosquitto (`mosquitto.service`) with ACL/password files under
  `/var/lib/iot-gateway-agent/mosquitto/`.
- Agent provides decrypt → `sensor_data.log`, Loki shipper, `/metrics`, `/v1/health`, mDNS.
- Provision and day-2 actions use SSH from the desktop app (no container engine).

## Control plane

- Sensor Registration: upsert Mosquitto ACL + password hash, optional CA-signed client cert download, `systemctl reload mosquitto`.
- Monitoring scrapes Prometheus job `iot-gateway-agent` (`instance=gateway`) on `:9139`.
