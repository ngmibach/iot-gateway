# Architecture (Docker-free)

## Operator PC

- Packaged app: `IoTGatewayMonitor.exe` (Windows) or AppImage (Linux).
- Local control service on `127.0.0.1:9137`; wizard/UI on `:9138`.
- Loki (`:3100`) and Prometheus (`:9090`) as native processes under the app data directory.
- Device registry in SQLite; secrets in the OS keyring (with file fallback).

## Gateway device

- `iot-gateway-agent` systemd unit under `/opt/iot-gateway-agent`.
- System Mosquitto (`mosquitto.service`) with **MQTTS :8883 mTLS only**
  (`require_certificate`, CA/server under `/var/lib/iot-gateway-agent/certs/`,
  ACL/password files under `/var/lib/iot-gateway-agent/mosquitto/`).
  Plaintext :1883 is not used for production ingress.
- Install bootstraps gateway CA + server cert (IP SAN). CA passphrase is
  generated or entered on Gateways → Install and stored in the operator
  keyring (`ca:{gateway_id}`); decrypt worker gets a `nodered` client cert.
- Kafka topic catalog under `/var/lib/iot-gateway-agent/kafka/topics.json`
  (one retention-capped topic per registered sensor).
- Apache Kafka KRaft single-node (`/opt/kafka`, systemd `iotgw-kafka`,
  `127.0.0.1:9092`, heap 128–256M) applies `retention.bytes` per topic.
  Redpanda is not used.
- Agent provides decrypt (mTLS client on :8883) → `sensor_data.log` → Kafka
  produce, Loki shipper, `/metrics` (incl. per-device + denied/IDS),
  `/v1/health`, mDNS.
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

## Gateway Activities (Monitoring)

Operator view of gateway-wide and per-sensor activity:

| Section | Content |
|---------|---------|
| Gateway select | Registry gateway **name only** (no IP in the dropdown) |
| General | Total msgs, msgs/sec, denied, IDS + delay chart |
| Connected sensors | Table from registry: device, IP, Kafka topic, retention, monitor |
| Sensor detail | 1 sensor → panel; N sensors → horizontal name tabs |
| Per sensor | Counters + Kafka topic chart + delay chart |

API: `GET /api/v1/query/summaries/gateway?gateway_id=&range=`  
Sources: registry device meta (`kafka_topic`), live catalog SSH sync,
Prometheus `iotgw_decrypt_*` / `iotgw_device_*` / denied / IDS, Loki fallback.

Shipped follow-ups checklist: `docs/plan-activities-kafka-followups.md`.

## Control plane

- Sensor Registration: upsert Mosquitto ACL + password hash, reserve Kafka
  topic, optional CA-signed client cert download, `systemctl reload mosquitto`.
- Monitoring scrapes Prometheus job `iot-gateway-agent` (`instance=gateway`) on `:9139`.
