# Plan: Gateway Activities / Kafka follow-ups

Deferred work after the Activities UI + registry/Kafka-topic summary landed.
Status updated as items ship.

## Checklist

1. **Kafka-compatible broker on the gateway** — **done**  
   Apache Kafka 3.7.1 in minimal KRaft single-node mode (not Redpanda):
   OpenJDK + `/opt/kafka`, systemd `iotgw-kafka`, heap 128–256M,
   `127.0.0.1:9092`. Topics created from
   `/var/lib/iot-gateway-agent/kafka/topics.json` with `retention.bytes`.
   Register creates/updates topics; unregister deletes them.

2. **Topic metrics into Prometheus** — **partial**  
   Agent exposes `iotgw_kafka_up`, `iotgw_kafka_produce_total`, and per-device
   message rates. Native Kafka JMX / topic retained-bytes exporter remains
   optional later work.

3. **Per-device agent counters** — **done**  
   `iotgw_device_messages_total`, `iotgw_device_denied_publishes_total`,
   `iotgw_device_ids_detections_total`, `iotgw_device_delay_ms` with
   `device_id` / `kafka_topic` labels.

4. **Replace legacy Loki denied / IDS queries** — **done**  
   Activities prefers `iotgw_denied_publishes_total` /
   `iotgw_ids_detections_total` (and per-device series). Loki
   `iot-nodered` / HAProxy expressions remain as fallback only.

5. **Live catalog sync** — **done**  
   `GET …/summaries/gateway` best-effort SSH-reads `topics.json` to fill topic
   / retention when registry meta is missing.

6. **Richer transmission delay** — **done (agent path)**  
   Agent derives delay from payload `delay` / timestamp fields into
   `iotgw_device_delay_ms`. Loki unwrap remains fallback.

7. **Packaged desktop release** — **pending ship**  
   After this lands on `windows` / `linux`, operators need a fresh
   `IoTGatewayMonitor.exe` from `desktop-latest` for bundled UI (Activities
   already shipped earlier; Kafka broker + agent metrics need reinstall /
   reprovision on the Pi).

## Related shipped pieces

- Capacity formula + catalog: registration playbooks + `kafka_capacity.py`.
- Broker provision: `provisioner/kafka_install.py` + `agent_install.py`.
- Agent produce + metrics: `kafka_producer.py`, `decrypt_worker.py`,
  `denied_watcher.py`, `metrics.py`.
- Activities IA: `monitoring.html` / `monitoring.js` + `GET …/summaries/gateway`.
- Docs: `README.md` (Gateway Activities), `docs/architecture.md`.
