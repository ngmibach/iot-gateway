# Plan: Gateway Activities / Kafka follow-ups

Deferred work after the Activities UI + registry/Kafka-topic summary landed.
Implement these in later sessions; they are intentionally out of the first
Activities refactor.

## Checklist

1. **Kafka-compatible broker on the gateway**  
   Install e.g. Redpanda (or Kafka) on the Pi during provision; create topics
   from `/var/lib/iot-gateway-agent/kafka/topics.json` with `retention.bytes`
   applied so disk caps are enforced by the broker, not only by registration math.

2. **Topic metrics into Prometheus**  
   Scrape Kafka/JMX or Redpanda metrics (topic size, produce rate, lag) so
   Activities Kafka charts show real retained-bytes / throughput instead of
   Loki/decrypt proxies or empty states.

3. **Per-device agent counters**  
   Extend `iot-gateway-agent` `/metrics` with `device_id` / `kafka_topic` labels
   for messages, denied publishes, and IDS so gateway and sensor cards do not
   depend on legacy Loki `iot-nodered` / HAProxy streams.

4. **Replace legacy Loki denied / IDS queries**  
   Retarget `queries.py` gateway denied/IDS expressions to Docker-free
   Mosquitto + agent labels; remove reliance on `container="iot-nodered"` and
   `iot-haproxy` once replacements are verified.

5. **Live catalog sync**  
   Optionally SSH-read `topics.json` on Activities refresh for topics present
   on the gateway but missing from the PC registry (repair / drift detection).

6. **Richer transmission delay**  
   End-to-end sensor→gateway timestamps (or broker produce latency) when
   current Loki `unwrap delay` labels are absent on the monolithic path.

7. **Packaged desktop release**  
   After Activities UI ships on `windows`, note in release notes that operators
   need a fresh `IoTGatewayMonitor.exe` from `desktop-latest` to see the new
   Activities panels (frozen UI is bundled at build time).

## Related shipped pieces

- Capacity formula + catalog: registration playbooks + `kafka_capacity.py`.
- Activities IA: `monitoring.html` / `monitoring.js` + `GET …/summaries/gateway`.
- Docs: `README.md` (Gateway Activities), `docs/architecture.md`.
