# Details

Depth behind the diagrams in [`architecture.md`](architecture.md). Operator UI steps are in [`UI.md`](UI.md).

## Monitoring stack

### Ports and processes

| Component | Bind | Notes |
|-----------|------|-------|
| Control service | `127.0.0.1:9137` | Registry, playbooks, query APIs |
| Wizard / UI | `127.0.0.1:9138` | Serves HTML/JS; proxies `/api/v1` |
| Loki | `:3100` | Native process; receives gateway shipper lines |
| Prometheus | `:9090` | Scrapes gateway agent `job=iot-gateway-agent` |
| Grafana | `https://127.0.0.1:9140` | Localhost HTTPS; opens in system browser |

Ready/start of the monitoring install requires Loki, Prometheus, and Grafana. Grafana OSS pin is documented in packaging (~445 MiB compressed); free-space preflight is ≥2.5 GiB. Self-signed Grafana cert is **download-only** from Settings → Certificates (no OS auto-import).

Provisioned Grafana datasources: Prometheus, Loki, and one Kafka datasource per registered gateway (`{gateway_ip}:9092` PLAINTEXT on trusted LAN).

### App data directories

| Platform | Path |
|----------|------|
| Windows | `%APPDATA%\IoTGatewayMonitor\` |
| Linux | `~/.local/share/iot-gateway-monitor/` |

Typical contents: settings, `registry.sqlite`, telemetry binaries, Chromium profile, control-service log, keyring fallback file.

### Registry and secrets

- **registry.sqlite** — gateways and devices. Monitoring Metric/Activities read gateways from the registry (settings.json SSH fields alone do not populate Monitoring).
- After successful **Install gateway**, the wizard upserts the provisioned gateway into the local registry (`shell/registry_gateways.py`).
- **Keyring** service name `iot-gateway-monitor` (file fallback `keyring-fallback.json`):
  - `ca:{gateway_id}` — CA signing passphrase
  - `sudo:{gateway_id}` — gateway sudo / SSH password for day-2 playbooks
  - Admin PIN for Settings → Admin

Wizard proxy injects keyring CA/sudo into Control Plane requests when the body omits them. Secrets are never written to settings.json or logs.

### Prometheus scrape

- Job name: `iot-gateway-agent`
- Target: `{gateway_ip}:9139/metrics`
- Instance label commonly `gateway`
- Template: `deploy/templates/prometheus.yml`

Wrong job names (for example legacy `node`) yield empty Metric panels while HTTP refresh can still succeed.

---

## Gateway agent stack

### Install layout

| Path | Purpose |
|------|---------|
| `/opt/iot-gateway-agent` | Agent package, venv, unit files |
| `/var/lib/iot-gateway-agent` | Data: certs, mosquitto ACL/passwords, kafka catalog, crypto, schemas, fake runtime, logs |
| `/opt/kafka` | Apache Kafka KRaft single-node |
| `/etc/iot-gateway-agent.env` | Agent environment (LF newlines) |
| `/etc/mosquitto/conf.d/iot-gateway-agent.conf` | System Mosquitto MQTTS listener config |

### Systemd / processes

| Unit / process | Role |
|----------------|------|
| `iot-gateway-agent` | Monolithic agent (`--no-broker`); health, metrics, decrypt, shipper |
| `mosquitto.service` | System Mosquitto; MQTTS `:8883` with `require_certificate` |
| `iotgw-kafka` | Kafka KRaft; heap 128–256M |
| `iotgw-fake@<id>` | Optional fake sensor simulator |

MQTT “up” is reported when TCP `127.0.0.1:1883` accepts (system broker), not only when an agent child broker is running. Production sensor ingress is **MQTTS `:8883` only**.

### MQTTS material

Under `/var/lib/iot-gateway-agent/`:

- `certs/` — CA, server cert (IP SAN), decrypt `nodered` client cert, daily DMEC under `certs/day/`
- `mosquitto/acl`, `mosquitto/passwords` — owned `mosquitto:mosquitto` (day-2 writes use sudo temp + mv)

### Kafka listeners

| Listener | Bind | Use |
|----------|------|-----|
| INTERNAL | `127.0.0.1:9092` | Agent produce |
| EXTERNAL | `{gateway_ip}:9092` | Desktop Grafana datasource (PLAINTEXT; trusted-LAN only) |

Catalog: `/var/lib/iot-gateway-agent/kafka/topics.json`. Topic name: `sensor.<device_id>`.

### Sensor capacity (Kafka)

```
max_sensors = floor(total_gateway_disk × 0.70 / topic_retention_bytes)
```

Example: disk=10, topic cap=1 → max **7** sensors. Only 70% of disk is budgeted for Kafka retention; 30% remains for OS, Mosquitto, logs, and agent.

- `GET /api/v1/gateways/{gid}/kafka/capacity`
- Register / create-fake returns **409** when full
- Re-register does not consume an extra slot
- Unregister drops the catalog entry
- Fakes count toward the same cap

---

## Verification and data path

### Register playbook (real or fake)

On Control Plane register / create-fake the control service typically:

1. Probes gateway disk and Kafka catalog for capacity
2. Upserts Mosquitto password hash + ACL
3. Signs a CA client cert (real sensors: downloadable zip; fakes: app-fed only)
4. Reserves Kafka topic with `retention.bytes` from catalog defaults
5. Writes device crypto + schema under `crypto/` and `schemas/`
6. Reloads Mosquitto (`systemctl`)
7. For fakes: netns + unit install (unit left **stopped** until Simulate → Start)

### Runtime path after publish

1. Sensor connects MQTTS `:8883` (password + client cert)
2. Mosquitto enforces ACL
3. Decrypt worker (mTLS client on `:8883`) receives payload
4. Envelope pair/open or legacy Fernet decrypt
5. Schema validate — deny on failure (no log, no Kafka)
6. Append `sensor_data.log`; produce Kafka; shipper tails to Loki

### Health and crypto HTTP

| Endpoint | Role |
|----------|------|
| `GET :9139/v1/health` | Agent health (includes MQTT mode/up) |
| `GET :9139/metrics` | Prometheus exposition |
| `GET :9139/v1/crypto/day/current` | Current DMEC public material |

---

## Encryption (envelope v1)

Canonical application-layer crypto for `iot-gateway-agent`.

### Layers

| Layer | Mechanism | Role |
|-------|-----------|------|
| Transport | MQTTS `:8883` (password + client cert, `require_certificate`) | Who may connect |
| Application | Envelope v1 (`v1-psk` / `v1-ecdhe`) | Confidentiality of JSON after TLS termination |
| Application | Registered JSON schema | Shape/types after decrypt |
| Application | Daily Message Encryption Certificate (DMEC) | Day-scoped wrap material (`day_id`) |

mTLS is not replaced by envelope crypto. The gateway always decrypts so it can schema-validate, write `sensor_data.log`, and produce Kafka.

### Why envelope (vs legacy Fernet)

Legacy wrappers put a fresh Fernet key inside the same JSON as the ciphertext:

```json
{"key":"<urlsafe-b64>","encrypted":"<Fernet token>"}
```

Anyone who can read Mosquitto payloads after TLS termination can decrypt. Envelope v1:

- Generates a per-message AES-128 content key (CEK)
- Publishes **wrapped key** and **ciphertext on separate MQTT topics**
- Binds both halves with an HMAC stamp from a registration-time `mac_key`
- Optionally wraps the CEK with CA-signed daily material (`v1-ecdhe`)

Legacy Fernet remains accepted while `IOTGW_ENVELOPE_REQUIRE` is off (default).

### Profiles

| Profile | CEK wrap | Typical use |
|---------|----------|-------------|
| `v1-psk` | Registration `wrap_secret` + HKDF(`day_id`) → AES-GCM wrap | Tiny / MCU sensors, lab fakes |
| `v1-ecdhe` | Ephemeral P-256 ECDH with today’s DMEC public key → AES-GCM wrap | Sensors that can do ECC |

Both profiles use:

- **Content:** AES-128-GCM (12-byte nonce, AAD = `msg_id ‖ day_id ‖ schema_id`)
- **Binding stamp:** HMAC-SHA256 over canonical `msg_id ‖ day_id ‖ schema_id ‖ wrapped_key ‖ nonce ‖ ciphertext`
- **Wire version:** `"v": 1`

### Wire format (dual MQTT topics)

| Topic | Body |
|-------|------|
| `sensors/{device_id}/env/key` | `{ "v", "msg_id", "day_id", "schema_id", "alg", "wrapped_key", "wrap_nonce", "stamp" [, "eph_pub"] }` |
| `sensors/{device_id}/env/data` | `{ "v", "msg_id", "day_id", "nonce", "ciphertext", "stamp" }` |

- `alg` is `v1-psk` or `v1-ecdhe`
- `eph_pub` is present only for `v1-ecdhe`
- Binary fields are **urlsafe base64 without padding**
- Decrypt worker pairs halves by `(device_id, msg_id)` within `IOTGW_ENVELOPE_PAIR_TIMEOUT` (default 5s)

### Seal → open flow

```text
Sensor                         Gateway decrypt worker
──────                         ──────────────────────
schema check (local copy)
CEK, nonce, msg_id ← random
ciphertext ← AES-GCM(CEK, …)
wrapped_key ← Wrap(profile, CEK)
stamp ← HMAC(mac_key, …)
PUB env/key + env/data  ──►    pair by msg_id
                               verify stamps
                               check day_id ∈ {y,t,t+1}
                               unwrap CEK
                               AES-GCM open
                               schema validate
                               → sensor_data.log / Kafka
```

### Registration material

On device register / create-fake, the control plane provisions:

| Store | Path / API |
|-------|------------|
| Device secrets | `/var/lib/iot-gateway-agent/crypto/devices/{device_id}.json` |
| Schema | `/var/lib/iot-gateway-agent/schemas/{schema_id}.json` |
| Bundle | Included in cert download / fake runtime feed |

Device secrets JSON (PSK example):

```json
{
  "device_id": "oven-1",
  "profile": "v1-psk",
  "mac_key": "<b64>",
  "wrap_secret": "<b64>",
  "schema_id": "default"
}
```

Agent helpers: `iot_gateway_agent.envelope_v1` (`generate_device_secrets`, `seal`, `open_envelope`, topic helpers). Control-service mirror: `actions/device_crypto.py`.

### Schema validation

After a successful open, the decrypt worker validates plaintext against the registered schema (`schema_validate.py` — compact JSON Schema subset: `string`, `integer`, `number`, `boolean`, `object`, `array`). Failures deny the message.

Example:

```json
{
  "schema_id": "default",
  "type": "object",
  "additionalProperties": true,
  "required": ["device_id", "hello"],
  "properties": {
    "device_id": { "type": "string" },
    "hello": { "type": "integer" },
    "ts_ms": { "type": "integer" }
  }
}
```

### Daily Message Encryption Certificate (DMEC)

- Issued under `/var/lib/iot-gateway-agent/certs/day/{day_id}.crt` + `.key` (`day_id = YYYYMMDD`, gateway-local date)
- P-256 keypair; cert signed by the gateway CA when CA material is available
- Private key stays on the gateway; sensors pull the public cert
- HTTP: `GET http://<gateway>:9139/v1/crypto/day/current`
- Decrypt accepts a short skew window (`yesterday` / `today` / `tomorrow`)

`v1-psk` still embeds `day_id` in the wrap KDF so stale days fail even without ECDH.

### Feature flags (`/etc/iot-gateway-agent.env`)

| Env | Default | Meaning |
|-----|---------|---------|
| `IOTGW_ENVELOPE_V1` | on | Accept `sensors/+/env/key|data` |
| `IOTGW_ENVELOPE_REQUIRE` | off | Deny legacy Fernet / cleartext |
| `IOTGW_ENVELOPE_PAIR_TIMEOUT` | 5 | Seconds to pair key + data |
| `IOTGW_ENVELOPE_REPLAY_CACHE` | 4096 | Recent `msg_id` anti-replay size |

### Metrics and deny reasons

Prometheus (`:9139/metrics`):

- `iotgw_envelope_messages_total{result="ok|fail"}`
- Existing decrypt / device / denied counters still apply for legacy and transport failures

Envelope open failures raise typed reasons (`version`, `stamp`, `day`, `unwrap`, `gcm`, pairing timeout, schema). Fail closed: no `sensor_data.log` line and no Kafka produce.

### Code map

| Component | Path |
|-----------|------|
| Seal / open / topics | `gateway/agent/iot_gateway_agent/envelope_v1.py` |
| Pairing + flags | `gateway/agent/iot_gateway_agent/decrypt_worker.py` |
| DMEC | `gateway/agent/iot_gateway_agent/day_crypto.py` |
| Device secret I/O | `gateway/agent/iot_gateway_agent/device_crypto.py` |
| Schema check | `gateway/agent/iot_gateway_agent/schema_validate.py` |
| Legacy Fernet | `gateway/agent/iot_gateway_agent/encrypt.py` / `decrypt.py` |
| Fake seal path | `gateway/agent/iot_gateway_agent/fake_sensor/simulator.py` |
| Registration crypto | `apps/control-service/actions/device_crypto.py` |
| Day HTTP | `GET /v1/crypto/day/current` in `server.py` / `main.py` |

### Operator checklist

1. MQTTS `:8883` up; decrypt worker log shows envelope enabled.
2. Device has `crypto/devices/<id>.json` + matching schema.
3. Sensor (or fake) seals and publishes **both** env topics.
4. Confirm plaintext in `/var/lib/iot-gateway-agent/logs/sensor_data.log`.
5. Confirm `iotgw_envelope_messages_total{result="ok"}` increments.

When ready to retire Fernet on a gateway, set `IOTGW_ENVELOPE_REQUIRE=1` and restart `iot-gateway-agent`.

---

## Gateway lifecycle

### Provision (Install gateway)

Desktop → SSH:

1. Discover open SSH on monitoring LAN (`POST /api/wizard/discover/gateways`)
2. Fetch/pin host key; install operator SSH public key
3. Optional Windows firewall apply for Loki `:3100` when elevated
4. `provisioner` / `agent_install`: apt deps, extract agent, configure system Mosquitto, bootstrap CA + server + decrypt certs, install Kafka, write env, enable/restart units
5. Save keyring `ca` + `sudo`; upsert registry row

CA passphrase: Generate (default) or manual entry (reject passphrase `admin`). Stored once after success as `ca:{gateway_id}`.

### Uninstall

| Action | Effect |
|--------|--------|
| Gateways → Clean up | Remove one gateway agent over SSH; monitoring stack stays |
| Settings → Remove | Uninstall Loki/Prometheus/Grafana + wipe local app data; also removes registered gateways when possible |

Gateway uninstall runs `teardown_all_fakes` (units, netns, bridge, fake data dir) then removes the agent install.

---

## Fake sensors

### Runtime topology

| Piece | Value |
|-------|-------|
| Bridge | `iotgw-fake` on `10.255.0.0/24`, gateway `10.255.0.1` |
| Netns | `iotgw-fake-<device_id>` |
| IP map | `/var/lib/iot-gateway-agent/fake/ip-map.json` |
| Unit | `iotgw-fake@<device_id>.service` |
| Payload file | `fake/<device_id>/payload.json` (default `{"device_id","hello":1}`) |
| Publish topic | `sensors/<device_id>/process` (envelope uses env/key + env/data) |

Create leaves the unit **stopped**. Start/stop and interval/topic/payload/behaviors are on **Simulate**.

### Cert lifecycle

- Fakes: monitoring app **auto-renews and feeds** mTLS (`FakeCertRenewer`); no operator cert zip / fingerprint / Re-issue UI
- Real sensors: one-time cert zip download + View → Re-issue cert
- TLS attack toggles (`omit_client_cert`, `wrong_client_cert`) pause auto-feed until cleared
- Disable renewer: `IOTGW_FAKE_CERT_RENEWER=0`

Renew window: `min(30d, 10% of client_cert_days)`. Loop ~10 minutes with immediate first pass.

### Privileged steps

Netns/bridge/unit and some day-2 Mosquitto/Kafka file writes need sudo on the gateway. Prefer keyring sudo from Install; otherwise the UI asks once.

---

## Query and Activities data sources

### APIs

| API | UI consumer |
|-----|-------------|
| `GET /api/v1/query/summaries/raspi?range=` | Gateway Metric |
| `GET /api/v1/query/summaries/gateway?gateway_id=&range=` | Gateway Activities |
| `GET /api/v1/gateways` | Gateway selectors |
| `GET /api/v1/gateways/{id}/devices` | Control Plane / Activities sensors |

### Metric series (high level)

- Host: node_exporter-compat gauges from agent `/proc` scrape
- Apps: `iotgw_app_up{app=…}`, CPU/mem where available; MQTT via TCP probe; Kafka may fall back to `iotgw_kafka_up`
- Activities: `iotgw_decrypt_*`, `iotgw_device_*`, denied/IDS; Kafka topic labels from registry + live `topics.json` SSH sync; Loki as fallback for some legacy queries
- Envelope: `iotgw_envelope_messages_total{result=…}`

Chart frames stay visible with “No data in range” until scrapes fill in.

### Applications order (Metric)

Fixed canonical order: **Agent → MQTT → Decrypt → Shipper → Kafka**.

---

## Samples

- Manufacturing-style Simulate payload: [`samples/fake-sensor-payload.json`](samples/fake-sensor-payload.json)
)
