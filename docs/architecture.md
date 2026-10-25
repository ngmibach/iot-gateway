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
- Kafka topic catalog under `/var/lib/iot-gateway-agent/kafka/topics.json`
  (one retention-capped topic per registered sensor). Broker install that
  enforces `retention.bytes` is a follow-up; registration already reserves
  topics and enforces disk capacity.
- Agent provides decrypt → `sensor_data.log`, Loki shipper, `/metrics`, `/v1/health`, mDNS.
- Provision and day-2 actions use SSH from the desktop app (no container engine).

## Sensor capacity (Kafka)

```
max_sensors = floor(total_disk × 0.70 / topic_retention_bytes)
```

Example: disk=10, topic cap=1 → max 7 sensors (70% of disk reserved for Kafka
retention; 30% headroom for OS / Mosquitto / logs / agent).

- `GET /api/v1/gateways/{gid}/kafka/capacity`
- Register returns HTTP 409 when capacity is full.
- Topic name: `sensor.<device_id>`.

## Control plane

- Sensor Registration: upsert Mosquitto ACL + password hash, reserve Kafka
  topic, optional CA-signed client cert download, `systemctl reload mosquitto`.
- Monitoring scrapes Prometheus job `iot-gateway-agent` (`instance=gateway`) on `:9139`.
