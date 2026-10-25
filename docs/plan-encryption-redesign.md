# Plan: Sensor payload encryption redesign

Status: **implemented on branch `windows`** (Stages 1–7 foundation).  
Audience: gateway agent, Control Plane registration, fake-sensor Simulate lab.  
Related code: `envelope_v1.py`, `schema_validate.py`, `day_crypto.py`, `device_crypto.py`,
`decrypt_worker.py`, `fake_sensor/simulator.py`, `actions/device_crypto.py`.

### Feature flags

| Env | Default | Meaning |
|-----|---------|---------|
| `IOTGW_ENVELOPE_V1` | on | Accept envelope topics |
| `IOTGW_ENVELOPE_REQUIRE` | off | Deny legacy Fernet / cleartext |
| `IOTGW_ENVELOPE_PAIR_TIMEOUT` | 5 | Seconds to pair key+data |
| `IOTGW_ENVELOPE_REPLAY_CACHE` | 4096 | Recent `msg_id` anti-replay size |

---

## 1. Current behavior (what the repo does today)

### 1.1 Application-layer crypto

Sensors (and fakes) seal the JSON body with a **Fernet-compatible** token
(AES-128-CBC + HMAC-SHA256), then publish one MQTT string:

```json
{"key":"<urlsafe-b64 32-byte key>","encrypted":"<Fernet token>"}
```

- `encrypt_wrapper_payload()` generates a **fresh key per message** when none is
  supplied and **embeds that key in the same JSON** as the ciphertext.
- `decrypt_wrapper_payload()` reads `key` + `encrypted` from that single object
  and decrypts. Missing fields → passthrough of raw JSON (no deny).
- Fake-sensor lab toggles: `skip_encryption`, `bad_encryption` (HMAC-corrupt).

There is **no second application encrypt** of the wrapper today. What feels like
“encrypt twice” in production is:

1. **Application Fernet** (confidentiality of the JSON body), and  
2. **MQTTS / TLS** (confidentiality of the whole MQTT frame on the wire).

TLS protects transit. It does **not** fix the design flaw that the Fernet key
travels next to the ciphertext. Anyone who can read Mosquitto payloads after TLS
termination (broker disk, ACL mistake, decrypt-worker bug, log leak) can decrypt
every message with no extra secret.

### 1.2 What is missing today

| Gap | Today |
|-----|--------|
| Key separate from ciphertext | No — key inside wrapper |
| Binding signature across key + body | No — only Fernet internal HMAC |
| Per-device secret from registration | No — ephemeral key per message |
| Registered JSON schema / types | No — any JSON accepted after decrypt |
| Daily gateway-issued crypto material | No — only long-lived mTLS client certs |
| Deny on bad crypto / bad schema | Partial — decrypt fail increments `messages_fail`; cleartext still accepted |
| Fake checklist for new failure modes | Only skip / corrupt Fernet |

mTLS client certs remain the **transport identity** layer and stay as-is.
This plan adds a stronger **application envelope** on top.

---

## 2. Goals (target model)

1. **Registration-time device formula (envelope profile)**  
   Generated **once** when the sensor is registered. Stored on the gateway and
   provisioned to the sensor. The sensor calls one function:

   ```text
   encrypt(payload_bytes) → (msg_id, wrapped_key, ciphertext, stamps…)
   ```

2. **Key and ciphertext travel separately**  
   Bound by a shared `msg_id` + stamps so the gateway can pair them and reject
   orphans / swaps.

3. **Message shape registered first**  
   Uniform JSON must match a registered schema (field names + datatypes).  
   Decrypt → validate → accept; else deny.

4. **Daily gateway crypto material (CA-backed)**  
   Sensors encrypt under material the gateway issues fresh each day (signed by
   the gateway CA). Wrong / missing / stale day material → gateway denies.

5. **Edge-light and gateway-fast**  
   Prefer AES-GCM (one-pass AEAD) and small keys; avoid per-message RSA on tiny
   MCUs. Decrypt path must stay cheap on the Pi (batchable, no heavy PKI per msg).

6. **Fake-sensor lab** expands to cover false encryption and schema attacks.

---

## 3. Design principles (crypto choices)

### 3.1 Do not “encrypt with the CA certificate” literally

A CA cert is for **signing / verifying**, not for bulk payload encryption.
Encrypting every sensor reading with the CA public key (RSA) is too heavy for
small sensors and too slow to unwrap at volume on the gateway.

**Interpretation used in this plan:**

- Gateway CA signs a short-lived **Daily Message Encryption Certificate (DMEC)**
  (or publishes a CA-signed **day blob**).
- Sensors use that day’s **public key only to wrap a small AES content key**
  (hybrid encryption), or — for the lightest devices — use a **registration PSK
  + day_id** AEAD wrap that the gateway can verify because it issued the day
  material.
- Bulk payload always uses **AES-128-GCM** (or ChaCha20-Poly1305 on MCUs without
  AES hardware).

### 3.2 Recommended algorithms (default profile `v1`)

| Piece | Choice | Why |
|-------|--------|-----|
| Content encryption | AES-128-GCM | Authenticated, one pass, MCU-friendly with hardware AES |
| Content key (CEK) | 16 random bytes per message | Forward secrecy at message grain |
| Key wrap | ECDH P-256 (ephemeral) → HKDF → AES-KW/GCM wrap of CEK **or** PSK+day HKDF wrap | Hybrid when MCU allows; PSK path for tiniest sensors |
| Binding stamp | HMAC-SHA256 over `msg_id ‖ day_id ‖ wrapped_key ‖ nonce ‖ ciphertext` with device MAC key | Pairs key↔payload; detects swap/replay mixups |
| Day material | CA-signed DMEC / day blob, TTL ≤ 24h, `day_id = YYYYMMDD` (gateway local date) | Fresh daily; deny if wrong |
| Schema | Compact JSON Schema subset (types: int, number, string, bool, object, array) | Cheap validation after decrypt |

**Profile split (so one codebase serves both Pi Python sensors and tiny MCUs):**

- **`v1-ecdhe`** — ephemeral P-256 + AES-GCM (preferred when `cryptography` / mbedTLS available).  
- **`v1-psk`** — registration PSK + day_id HKDF wrap (fallback for very small sensors).

Both share the same wire fields and gateway decrypt worker.

### 3.3 What the “registration formula” actually is

At register time the gateway generates and stores:

```text
device_crypto = {
  profile: "v1-ecdhe" | "v1-psk",
  device_id,
  schema_id,
  mac_key,          # HMAC stamp key (gateway + device)
  wrap_secret,      # PSK path only (or device static ECDH public key)
  device_ecdh_pub,  # ecdhe path
}
```

The sensor SDK exposes:

```text
seal(json_obj) -> EnvelopeParts
```

Internally:

1. Validate `json_obj` against the **local copy** of the registered schema (fail closed before send).  
2. `CEK ← random(16)`, `nonce ← random(12)`, `msg_id ← random(16)`.  
3. `ciphertext ← AES-GCM(CEK, nonce, plaintext)` with AAD = `msg_id ‖ day_id ‖ schema_id`.  
4. `wrapped_key ← Wrap(day_public_or_psk, CEK)`.  
5. `stamp ← HMAC(mac_key, msg_id ‖ day_id ‖ schema_id ‖ wrapped_key ‖ nonce ‖ ciphertext)`.  
6. Return parts for separate publish.

Gateway reverse:

1. Pair by `msg_id` (and `device_id` from MQTT topic).  
2. Verify stamp(s).  
3. Check `day_id` is today (or today±skew window).  
4. Unwrap CEK with gateway day private key / device PSK.  
5. AES-GCM open.  
6. Schema-validate.  
7. Else deny (counters + optional IDS bump).

---

## 4. Wire format (key and payload sent separately)

### 4.1 Two MQTT publications (recommended)

Same QoS, short pairing window (e.g. 5s) on the decrypt worker.

| Topic | Body (JSON, small) |
|-------|--------------------|
| `sensors/{device_id}/env/key` | `{ "v":1, "msg_id", "day_id", "schema_id", "alg", "wrapped_key", "stamp" }` |
| `sensors/{device_id}/env/data` | `{ "v":1, "msg_id", "day_id", "nonce", "ciphertext", "stamp" }` |

- Gateway matches `msg_id` + `device_id` + matching `day_id`.  
- Each part carries its own `stamp` over the **same** canonical bytes so either
  part alone is useless and a swapped key from another message fails HMAC.  
- Optional single-topic fallback for constrained brokers:
  `sensors/{device_id}/env` with `{key: {...}, data: {...}}` — still logically
  separate objects, still stamped; use only if dual publish is impractical.

### 4.2 Why stamps on both

Without stamps, an attacker who can publish on one topic could attach a stolen
`wrapped_key` to a different ciphertext (or replay). HMAC with the registration
`mac_key` binds both halves to one sealing event. TLS/mTLS remains mandatory;
stamps defend the application layer after TLS termination.

### 4.3 Deny policy (fail closed)

Decrypt worker **rejects** (no Kafka, no `sensor_data.log` line) when:

- Either half missing after timeout  
- Stamp mismatch  
- Unknown / expired `day_id`  
- Unwrap / GCM auth failure  
- Schema mismatch (missing field, wrong type, extra field if schema is closed)  
- Device not registered / crypto profile missing  

Cleartext passthrough of today’s wrapper **goes away** after Stage 2 cutover.

---

## 5. Schema registration

### 5.1 Lifecycle

1. Operator (or sensor onboarding API) registers a **message schema** on the
   gateway before or during device register.  
2. Schema stored under `/var/lib/iot-gateway-agent/schemas/{schema_id}.json`
   and referenced from device meta (`schema_id`).  
3. Device receives schema copy in the cert/crypto bundle download.  
4. Every decrypted message must validate; gateway is source of truth.

### 5.2 Schema shape (compact subset)

Example:

```json
{
  "schema_id": "temp-v1",
  "type": "object",
  "additionalProperties": false,
  "required": ["device_id", "ts_ms", "temp_c"],
  "properties": {
    "device_id": { "type": "string", "const": "@device_id" },
    "ts_ms": { "type": "integer", "minimum": 0 },
    "temp_c": { "type": "number" },
    "ok": { "type": "boolean" }
  }
}
```

Supported types for v1: `string`, `integer`, `number`, `boolean`, `object`,
`array` (with `items`). Keep validators dependency-light on the agent
(hand-rolled subset or a tiny embedded checker — avoid pulling full
jsonschema if it hurts Pi startup).

### 5.3 Control Plane UX (later stage)

Registration / View: pick or paste schema, show schema_id, validate sample
payload in UI before save. Fake Simulate payload editor warns when sample
violates schema.

---

## 6. Daily CA-backed material

### 6.1 Daily Message Encryption Certificate (DMEC)

Once per gateway-local day (cron / agent timer around local midnight + on boot):

1. Generate day keypair (P-256).  
2. Issue cert with SANs/`day_id`, `notBefore`/`notAfter` ~24h, signed by gateway CA.  
3. Store private key **only on gateway** under
   `/var/lib/iot-gateway-agent/certs/day/{day_id}.key` (mode 0600).  
4. Publish public cert to sensors:
   - MQTT retained: `gateway/crypto/day/{day_id}` (PEM or compact SPKI), and/or  
   - HTTPS on agent `:9139/v1/crypto/day/current` for pull on wake.  
5. Sensors import/replace “today’s” public material; refuse to seal if missing
   or not CA-signed / not yet valid / expired.

### 6.2 Sensor obligation

If DMEC is not imported correctly, `seal()` fails locally and nothing valid is
published — gateway also denies any message with wrong `day_id` or unwrap
failure. That matches “gateway will deny” even when a confused sensor still
tries to send.

### 6.3 Skew and rotation

- Accept `day_id ∈ {yesterday, today, tomorrow}` for a short overlap window
  (e.g. ±2h around midnight) so devices with clock drift still work.  
- Metrics: `iotgw_crypto_day_ok`, `iotgw_crypto_day_stale`, deny reasons.

### 6.4 Relation to existing mTLS client certs

| Layer | Material | Lifetime | Role |
|-------|----------|----------|------|
| Transport | Client cert + MQTT password | Days–months (reissue API exists) | Who may connect |
| Application | Registration mac/wrap secrets | Device lifetime (rotate on re-register) | Bind envelope |
| Application | DMEC / day_id | ~24h | Fresh wrap target; deny stale crypto |

Do **not** replace mTLS with day certs. Keep both.

---

## 7. Performance budget (edge + gateway)

Target budgets (order-of-magnitude; measure in Stage 5):

| Step | Tiny sensor (PSK path) | Pi Python sensor (ECDHE) | Gateway decrypt / msg |
|------|------------------------|---------------------------|------------------------|
| Schema check (pre) | &lt; 1 ms | &lt; 1 ms | &lt; 1 ms |
| AES-GCM seal/open ~256 B | &lt; 1 ms | &lt; 1 ms | &lt; 1 ms |
| Key wrap | HKDF+AES &lt; 1 ms | ECDH P-256 ~2–5 ms | ECDH or PSK unwrap ~same |
| HMAC stamp | &lt; 1 ms | &lt; 1 ms | &lt; 1 ms |
| **Total seal** | **≲ 5 ms** | **≲ 10 ms** | **unwrap+validate ≲ 10 ms** |

Optimizations:

- Cache today’s DMEC private key in decrypt-worker memory.  
- Index pending `msg_id` in a dict with TTL (pair key/data).  
- Prefer PSK profile on 8-bit / tiny Cortex-M without HW ECC.  
- Keep ciphertext small: compact JSON separators, no pretty-print.  
- Stay on AES-GCM; drop Fernet CBC+HMAC (two-pass) during cutover.

---

## 8. Fake-sensor checklist (false encryption & related denials)

Extend Control Plane → Simulate behaviors. Each row must produce a **visible
deny** (Activities denied / decrypt fail / IDS as designed).

### 8.1 Existing (keep)

| ID | Behavior | Expected |
|----|----------|----------|
| F1 | `omit_client_cert` | MQTTS connect fail |
| F2 | `wrong_client_cert` | MQTTS connect fail |
| F3 | `wrong_password` | MQTTS auth fail |
| F4 | `wrong_topic` | ACL deny |
| F5 | `skip_encryption` | App-layer deny (after cutover; no passthrough) |
| F6 | `bad_encryption` | GCM/HMAC fail → decrypt fail |

### 8.2 New crypto / envelope cases

| ID | Behavior | How to simulate | Expected |
|----|----------|-----------------|----------|
| F7 | `key_only` | Publish env/key, never data | Pairing timeout deny |
| F8 | `data_only` | Publish env/data, never key | Pairing timeout deny |
| F9 | `stamp_mismatch_key` | Flip byte in key stamp | Deny (stamp) |
| F10 | `stamp_mismatch_data` | Flip byte in data stamp | Deny (stamp) |
| F11 | `swapped_msg_id` | Key msg_id ≠ data msg_id | Deny (unpaired / stamp) |
| F12 | `wrong_day_id` | Seal with yesterday outside skew or random day | Deny (day) |
| F13 | `missing_day_material` | Delete DMEC on fake; try seal/send | Local seal fail or gateway unwrap deny |
| F14 | `wrong_day_public` | Import unrelated public key | Unwrap deny |
| F15 | `replay_envelope` | Resend same key+data later | Deny if anti-replay window enabled (Stage 4+) |
| F16 | `schema_missing_field` | Drop required field before seal | Local or gateway schema deny |
| F17 | `schema_wrong_type` | Send string where integer required | Schema deny |
| F18 | `schema_extra_field` | Add undeclared field when `additionalProperties: false` | Schema deny |
| F19 | `wrong_schema_id` | Stamp a different schema_id | Deny |
| F20 | `foreign_device_mac` | Seal with another device’s mac_key | Stamp deny |
| F21 | `legacy_fernet_wrapper` | Send old `{"key","encrypted"}` after cutover | Deny (unknown version) |

UI: short toggle labels only (same pattern as today’s Simulate tips).  
Metrics: label deny reason on `iotgw_device_*` / decrypt fail counters where cheap.

---

## 9. Staged rollout

Each stage is shippable on `windows` then ported to `linux`. Prefer feature
flags (`IOTGW_ENVELOPE_V1=1`) so gateways can dual-run during migration.

### Stage 0 — Spec freeze & inventory (docs only)

- Agree this plan: profiles `v1-psk` / `v1-ecdhe`, dual-topic wire format,
  DMEC daily, schema subset.  
- Document migration from Fernet wrapper.  
- **Exit:** this file reviewed; no agent behavior change yet.

### Stage 1 — Envelope crypto library (agent, dual-run)

- Add `envelope_v1.py` (seal/open, stamps, AES-GCM).  
- Keep Fernet path working.  
- Unit tests: roundtrip, corrupt stamp, wrong key.  
- Fake sensor: optional `envelope_v1` mode behind config flag.  
- **Exit:** tests green; Fernet still default.

### Stage 2 — Decrypt worker pairing + fail-closed flag

- Subscribe `sensors/+/env/key` and `sensors/+/env/data`.  
- Pair by `msg_id`, TTL timeout, reason-coded denies.  
- Flag `IOTGW_ENVELOPE_REQUIRE=0` default (accept legacy wrapper).  
- Metrics for ok/fail/timeout.  
- **Exit:** can decrypt envelope from fake; legacy still works.

### Stage 3 — Registration provisions device crypto + schema_id

- On register / create-fake: generate `mac_key` (+ PSK or ECDH keys), store under
  gateway data dir (not in MQTT message).  
- Bundle in cert download zip.  
- Device meta: `schema_id`, `crypto_profile`.  
- API to upload/attach schema JSON.  
- **Exit:** new devices get secrets; old devices unchanged.

### Stage 4 — Schema validation on gateway

- Agent loads schemas; validate after successful open.  
- Deny F16–F19.  
- Control Plane: schema field on Registration (minimal UI).  
- **Exit:** wrong-shaped cleartext never hits Kafka/log.

### Stage 5 — Daily DMEC issuance + sensor import

- Agent timer issues/rotates day cert; expose MQTT retained + HTTP.  
- Seal() requires valid day public material.  
- Deny wrong/missing day (F12–F14).  
- Fake checklist rows enabled in Simulate.  
- **Exit:** day rollover tested; skew window documented.

### Stage 6 — Cutover & Fernet retirement

- Default `IOTGW_ENVELOPE_REQUIRE=1` for new provisions.  
- Reject legacy Fernet wrapper (F21).  
- Remove passthrough of cleartext JSON.  
- README + architecture update; Activities shows deny reasons.  
- **Exit:** no production path depends on key-inside-wrapper.

### Stage 7 — Hardening & performance

- Optional anti-replay cache (`msg_id` LRU).  
- Benchmark seal/open on Pi + fake; tune.  
- ChaCha20-Poly1305 alt profile if needed.  
- Docs: sensor SDK notes for external device vendors.  
- **Exit:** budgets met; checklist F1–F21 automated where possible.

---

## 10. Suggested PR / work breakdown (maps to stages)

| PR | Stage | Touchpoints (expected) |
|----|-------|------------------------|
| PR-A | 1 | `gateway/agent/.../envelope_v1.py`, tests, encrypt.py thin wrappers |
| PR-B | 2 | `decrypt_worker.py` pairing, metrics, feature flag |
| PR-C | 3 | `playbooks.py` register, bundle download, device meta, fake create |
| PR-D | 4 | schema store + validator, Control Plane schema field |
| PR-E | 5 | day cert rotate job, `/v1/crypto/day`, fake import, Simulate toggles |
| PR-F | 6 | require-envelope default, deny legacy, README/architecture |
| PR-G | 7 | replay cache, benches, remaining fake IDs, polish |

---

## 11. Security notes / non-goals

**In scope**

- Stop shipping the content key beside the ciphertext.  
- Bind key↔payload; schema gate; daily wrap material; lab denials.

**Out of scope (for this plan)**

- Replacing MQTTS mTLS.  
- End-to-end encryption that the gateway cannot decrypt (gateway must open
  payloads to validate, log, and Kafka-produce).  
- Encrypting Kafka topics at rest (separate follow-up).  
- Using the CA **private** key for message encryption (never).

**Threats this design addresses**

- Broker-local reader recovering Fernet key from wrapper JSON.  
- Cross-message key/ciphertext splicing.  
- Sensors that never enrolled schema or day material.  
- Lab verification of deny paths via fake sensors.

**Residual risks**

- Gateway compromise still exposes day private keys + device wrap secrets
  (inherent if gateway decrypts).  
- Clock sabotage can push devices outside day skew — monitor `day_stale`.  
- Dual-topic pairing needs TTL memory; size the map for max sensors × rate.

---

## 12. Open decisions (resolve before Stage 1 coding)

1. **Default profile for fakes:** `v1-psk` (simpler lab) vs `v1-ecdhe` (closer to “CA day cert wrap”). Recommendation: implement **both**, default fakes to `v1-ecdhe` once Stage 5 lands; allow PSK for “tiny sensor” simulate mode.  
2. **Dual MQTT topics vs single envelope object:** recommendation **dual topics** for true separation; single object as fallback flag.  
3. **Schema UI richness in Stage 4:** paste JSON only vs visual field builder. Recommendation: paste JSON + sample validate first.  
4. **Anti-replay in Stage 6 vs 7:** recommendation Stage 7 (needs memory/policy).  
5. **Day publish channel:** retained MQTT + HTTP both; sensors may use either.

---

## 13. Summary

Today the app layer is a single Fernet seal with the **key inside the message**,
plus MQTTS on the wire. The redesign introduces a registration-time seal
formula, **separate stamped key and data parts**, **schema registration**, and
**CA-signed daily wrap material**, with AES-GCM for light edge seal/open and a
staged migration that keeps Fernet until cutover. Fake-sensor Simulate grows
into a full false-encryption checklist (F1–F21) so denials are provable in the
Control Plane lab.
