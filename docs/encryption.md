# Envelope v1 — application payload encryption

Canonical reference for the **envelope v1** application-layer crypto used by
`iot-gateway-agent`. Design history and staged rollout notes live in
[`plan-encryption-redesign.md`](plan-encryption-redesign.md).

## Layers

| Layer | Mechanism | Role |
|-------|-----------|------|
| Transport | MQTTS :8883 (password + client cert, `require_certificate`) | Who may connect |
| Application | Envelope v1 (`v1-psk` / `v1-ecdhe`) | Confidentiality of JSON after TLS termination |
| Application | Registered JSON schema | Shape/types after decrypt |
| Application | Daily Message Encryption Certificate (DMEC) | Day-scoped wrap material (`day_id`) |

mTLS is **not** replaced by envelope crypto. The gateway always decrypts so it
can schema-validate, write `sensor_data.log`, and produce Kafka.

## Why envelope (vs legacy Fernet)

Legacy wrappers put a fresh Fernet key **inside the same JSON** as the
ciphertext:

```json
{"key":"<urlsafe-b64>","encrypted":"<Fernet token>"}
```

Anyone who can read Mosquitto payloads after TLS termination can decrypt.
Envelope v1:

- Generates a per-message AES-128 content key (CEK)
- Publishes **wrapped key** and **ciphertext on separate MQTT topics**
- Binds both halves with an HMAC stamp from a registration-time `mac_key`
- Optionally wraps the CEK with CA-signed daily material (`v1-ecdhe`)

Legacy Fernet remains accepted while `IOTGW_ENVELOPE_REQUIRE` is off (default).

## Profiles

| Profile | CEK wrap | Typical use |
|---------|----------|-------------|
| `v1-psk` | Registration `wrap_secret` + HKDF(`day_id`) → AES-GCM wrap | Tiny / MCU sensors, lab fakes |
| `v1-ecdhe` | Ephemeral P-256 ECDH with today’s DMEC public key → AES-GCM wrap | Sensors that can do ECC |

Both profiles use:

- **Content:** AES-128-GCM (12-byte nonce, AAD = `msg_id ‖ day_id ‖ schema_id`)
- **Binding stamp:** HMAC-SHA256 over canonical `msg_id ‖ day_id ‖ schema_id ‖ wrapped_key ‖ nonce ‖ ciphertext`
- **Wire version:** `"v": 1`

## Wire format (dual MQTT topics)

| Topic | Body |
|-------|------|
| `sensors/{device_id}/env/key` | `{ "v", "msg_id", "day_id", "schema_id", "alg", "wrapped_key", "wrap_nonce", "stamp" [, "eph_pub"] }` |
| `sensors/{device_id}/env/data` | `{ "v", "msg_id", "day_id", "nonce", "ciphertext", "stamp" }` |

- `alg` is `v1-psk` or `v1-ecdhe`.
- `eph_pub` is present only for `v1-ecdhe`.
- Binary fields are **urlsafe base64 without padding**.
- Decrypt worker pairs halves by `(device_id, msg_id)` within
  `IOTGW_ENVELOPE_PAIR_TIMEOUT` (default 5s).

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

## Registration material

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

Agent helpers: `iot_gateway_agent.envelope_v1.generate_device_secrets`,
`seal`, `open_envelope`, `key_topic`, `data_topic`.  
Control-service mirror: `actions/device_crypto.py`.

## Schema validation

After a successful open, the decrypt worker validates plaintext against the
registered schema (`schema_validate.py` — compact JSON Schema subset:
`string`, `integer`, `number`, `boolean`, `object`, `array`). Failures deny the
message (no log line, no Kafka produce).

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

## Daily Message Encryption Certificate (DMEC)

- Issued under `/var/lib/iot-gateway-agent/certs/day/{day_id}.crt` + `.key`
  (`day_id = YYYYMMDD`, gateway-local date).
- P-256 keypair; cert signed by the gateway CA when CA material is available.
- Private key stays on the gateway; sensors pull the public cert.
- HTTP: `GET http://<gateway>:9139/v1/crypto/day/current`
- Agent module: `day_crypto.ensure_day_material` / `load_day_public_key`.
- Decrypt accepts a short skew window (`yesterday` / `today` / `tomorrow`).

`v1-psk` still embeds `day_id` in the wrap KDF so stale days fail even without
ECDH.

## Feature flags (`/etc/iot-gateway-agent.env`)

| Env | Default | Meaning |
|-----|---------|---------|
| `IOTGW_ENVELOPE_V1` | on | Accept `sensors/+/env/key|data` |
| `IOTGW_ENVELOPE_REQUIRE` | off | Deny legacy Fernet / cleartext |
| `IOTGW_ENVELOPE_PAIR_TIMEOUT` | 5 | Seconds to pair key + data |
| `IOTGW_ENVELOPE_REPLAY_CACHE` | 4096 | Recent `msg_id` anti-replay size |

## Metrics and deny reasons

Prometheus (`:9139/metrics`):

- `iotgw_envelope_messages_total{result="ok|fail"}`
- Existing decrypt / device / denied counters still apply for legacy and
  transport failures

Envelope open failures raise typed reasons (`version`, `stamp`, `day`,
`unwrap`, `gcm`, pairing timeout, schema). Fail closed: no `sensor_data.log`
line and no Kafka produce.

## Code map

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

## Operator checklist

1. MQTTS :8883 up; decrypt worker log shows `envelope=True`.
2. Device has `crypto/devices/<id>.json` + matching schema.
3. Sensor (or fake) seals and publishes **both** env topics.
4. Confirm plaintext in `/var/lib/iot-gateway-agent/logs/sensor_data.log`.
5. Confirm `iotgw_envelope_messages_total{result="ok"}` increments.

When ready to retire Fernet on a gateway, set `IOTGW_ENVELOPE_REQUIRE=1` and
restart `iot-gateway-agent`.
