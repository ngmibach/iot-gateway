# Thesis Presentation — Structure Plan

**Working file:** `Thesis_Presentation_bg_only_new.pptx`

## Locked slides

| # | Title                   | Status                 |
| - | ----------------------- | ---------------------- |
| 1 | Title — IoT-SecureGate | Intact (do not change) |
| 2 | Team Responsibilities   | Intact (do not change) |

---

## Full talk order (updated)

| Order | Section                                         | Why this order                                                                         |
| ----- | ----------------------------------------------- | -------------------------------------------------------------------------------------- |
| A     | **Project Overview**                      | Problem, platform introduction, architecture                                           |
| B     | **Management & Monitoring**               | First technical deep-dive — highlights overall system structure and operator workflow |
| C     | **Security Core**                         | Admission, authentication, message protection                                          |
| D     | **Intelligent Protection**                | Behavioral detection on accepted traffic                                               |
| E     | **UI Demonstration**                      | Live / walkthrough of the management application                                       |
| F     | **Status vs Goals, Future Work, Closing** | Compare delivery to introduction aims; improvements; close                             |
| G     | **Q&A**                                   | Questions                                                                              |

---

## Section A — Project Overview

| # | Title                                              | Purpose                                                            | Status                                 |
| - | -------------------------------------------------- | ------------------------------------------------------------------ | -------------------------------------- |
| 3 | **Table of Contents**                        | Orient audience on full talk flow                                  | Done (user-edited)                     |
| 4 | **Problem Statement**                        | Three industrial edge-security problems → IoT-SecureGate response | **User-updated — do not touch** |
| 5 | **IoT-SecureGate Introduction**              | Three platform parts (one per student role)                        | **User-updated — do not touch** |
| 6 | **System Requirements**                      | Four theme cards from thesis FR/NFR                                | Built / user may restyle               |
| 7 | **Management & Monitoring (section opener)** | Bách section intro                                                | **User-added — do not touch**   |

## Section B — Management & Monitoring

| #      | Title                                            | Purpose                                      | Status                                 |
| ------ | ------------------------------------------------ | -------------------------------------------- | -------------------------------------- |
| 8      | **System Overview**                        | Cleaned top-level architecture diagram       | **Built**                        |
| 9      | **Centralized Monitoring Functions**       | Three-card operator functions                | **User-updated — do not touch** |
| 10     | **Centralized Monitoring Structure**       | Monitoring App process / stack / state graph | **User-updated — do not touch** |
| 11     | **Gateway & Device Management**            | Action → Resource matrix                     | **Built**                        |
| 12     | **Delivery Strategy**                      | Code → CI → installers → operator (NFR-10) | **Built**                        |
| 13–14 | Reserved / Metrics if needed               | Empty before Security Core opener            | Pending                                |

---

### Slide 3 — Table of Contents (approved content)

**Title:** Table of Contents

1. Project Overview
2. Management & Monitoring
3. Security Core
4. Intelligent Protection
5. UI Demonstration
6. Status, Future Work, and Closing
7. Q&A

---

### Slide 4 — Problem Statement

**Status:** User-updated in pptx — do not edit.

### Slide 5 — IoT-SecureGate Introduction

**Status:** User-updated in pptx — do not edit.

### Slide 6 — System Requirements (built)

**Title:** System Requirements

**Source:** `thesis-new.tex` Chapter 3 — FR-1–FR-14, NFR-1–NFR-10

**Brief summary (spoken, not all on slide):**
IoT-SecureGate must admit only registered devices over MQTTS with password + mTLS + ACL, protect and validate payloads, store accepted data, give the operator metrics/activity and deny/invalid alerts with block and auto-restrict, and ship as a usable Windows/Linux desktop app that provisions a modest Linux gateway on a trusted LAN.

**On-slide layout (built):** four navy cards + blue footer, matching slide 4 visual language (`#122845` cards, `#4596FD` accent / footer, `#F6F6F6` titles)

| #  | Theme card                       | Bullets on slide                                                                                                                    |
| -- | -------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| 01 | **Admission & Protection** | Registered devices only · Password + mTLS + ACL · Envelope decrypt & schema · Log + Kafka storage                                |
| 02 | **Visibility**             | Gateway health metrics · Transmission activity · Loki / Prometheus / Grafana                                                      |
| 03 | **Detection & Response**   | Deny / invalid alerts · Manual block / allow · Auto IP quarantine · Lab fake sensors                                             |
| 04 | **Deployability**          | Packaged Win / Linux app · SSH gateway provision · Register devices from UI · Secrets in OS keyring · Trusted LAN + CI delivery |

**Footer:** TWO RUNTIMES — Monitoring application (operator PC) · Gateway (edge host)

### Slide 7 — Management & Monitoring section opener

**Status:** User-added — do not edit.

### Slide 8 — System Overview (built)

**Title:** System Overview

**Master file:** `Thesis_Presentation_bg_only_new.pptx` (full deck — keep updating here)
**Delivery file:** `System_Overview.pptx` (this slide only)

**Diagram source:** `architecture/arch-toplevel-thesis-colors.html` → `architecture/iot-securegate-system-overview.png`

**Edits applied before placing on slide:**

- Removed top title `IoT-SecureGate — System Top-Level Architecture`
- Removed subtitle `One platform · two runtimes · components colored by thesis part`
- Renamed Shared agent → **API IoT Gateway Agent** (meta: *API server managing gateway activities*)
- Renamed zone header `Operator PC — Monitoring app` → **Monitoring App**
- Diagram canvas background matched to slide navy (`#00183D` → `#102E53` → `#001C41`)
- Kept color legend (Security Core / Intelligent Protection / Management & Monitoring / Shared · edge)

**Layout:** two-tone title + full-width diagram on navy gradient blank slide after the section opener.

### Slides 9–10 — Centralized Monitoring Functions / Structure

**Status:** User-updated in pptx — do not edit.

### Slide 11 — Gateway & Device Management · Action → Resource (built) — graph 1 of 3

**Title:** Gateway & Device Management · Action → Resource

**Master file:** `Thesis_Presentation_bg_only_new.pptx`
**Delivery file:** `Gateway_Device_Management.pptx` (this slide only)

**Diagram:** `architecture/arch-management-hierarchy.html` → `architecture/iot-securegate-management-hierarchy.png`

Full action matrix — each Monitoring App action maps to Gateway and/or Sensor resources:

**Outbound (App → resource)**

| App action                         | Gateway changes                             | Sensor experiences                   |
| ---------------------------------- | ------------------------------------------- | ------------------------------------ |
| Install / Remove gateway           | Agent · Mosquitto · Kafka · CA · scrape | —                                   |
| Register device / Create fake      | MQTT user · ACL · cert · Kafka topic     | New identity · publish rights       |
| Block / Restore publish            | Rewrite write ACL                           | Can/cannot publish                   |
| Arm Auto prevent / Lift quarantine | auto_prevent.json · firewall DROP          | Sensor IP dropped / released         |
| Clear Kafka history                | Recreate device stream                      | History emptied · registration kept |
| Fake Start / Stop / Simulate       | iotgw-fake@ · bridge · payload            | Lab unit runs / publishes            |
| IDS Enable / Disable               | IDS systemd only                            | Alerts only (no ACL change)          |

**Inbound (resource → App)**

| App view           | From gateway                              | From sensor                                  |
| ------------------ | ----------------------------------------- | -------------------------------------------- |
| Metric             | /metrics host + components                | aggregate health                             |
| Activities         | Counters · Loki · refusals              | Per-device volume · Fake/Real · quarantine |
| Alarm / IDS alerts | Invalid burst · quarantine · ids-alerts | Which device / IP                            |

### Slide 12 — Delivery Strategy (built) — final M&M graph

**Title:** Delivery Strategy

**Master file:** `Thesis_Presentation_bg_only_new.pptx`  
**Delivery file:** `Delivery_Strategy.pptx` (this slide only)

**Diagram:** `architecture/arch-delivery-strategy.html` → `architecture/iot-securegate-delivery-strategy.png`

Flow (thesis Fig. arch-delivery / NFR-10):
1. **Shared source tree** — one recipe · packaging branches · or manual CI run  
2. **Windows / Linux pipelines** — hosted runner → `.exe` + digest / AppImage + digest  
3. **Standing release** — assets replaced in place · one permanent address  
4. **Operator PC** — one manual download · install Monitoring App · no developer rebuild  

(NFR-10 footer text removed from the graph.)

---

## Section C — Security Core (refactored structure)

**Narrative arc:** Register once → admit at the wire → process inside the gateway → show how the sensor seals → show how the gateway opens.

**Why this replaces the old four-way split:**
Old titles mixed *setup* (registration), *transport auth* (mTLS/password), *app crypto* (envelope), and *ops* (replay/monitoring) as peer topics. The new order follows the **message path**: credentials first, then outer admission, then inner handling, then the two crypto halves (seal / open).

**Naming convention**

- Section opener: short role label + one-line promise.
- Flow slides: **noun + path** (`Outer Admission Path`, `Inner Processing Path`) — relation graphs first.
- Crypto pair: **actor + action** (`Sensor Encryption`, `Gateway Decryption`) — symmetric naming.
- Prefer *path / layer / stage* over *lightweight mutual authentication*, *session key establishment*, *credential management*.
- Stage numbers on graphs: **01 · 02 · 03 · …** (match System Requirements card style).
- Spoken depth lives in notes; on-slide text stays short labels + arrows.

**Slide number placeholders:** assign concrete deck indices when inserting after Management & Monitoring closes. Working labels: `SC-0` … `SC-5`.

| ID   | Working title                            | Format                    | Purpose                                                              | Status |
| ---- | ---------------------------------------- | ------------------------- | -------------------------------------------------------------------- | ------ |
| SC-0 | **Security Core** (section opener) | Title + agenda            | Open Thức’s part; preview the path                                 | Pending (skipped for now) |
| SC-1 | **Device Registration**            | Title + graph only        | What must exist before any message is accepted                       | **Built** → `Device_Registration.pptx` |
| SC-2 | **Outer Admission Path**           | Title + graph only        | Wire-level gates: mTLS → firewall/IP → password → ACL             | **Built** → `Outer_Admission_Path.pptx` |
| SC-3 | **Inner Processing Path**          | Title + graph only        | Decrypt → schema → topic binding → Kafka                           | **Built** → `Inner_Processing_Path.pptx` |
| SC-4 | **Sensor Encryption**              | Title + graph only        | Two protection layers on the sensor                                  | **Built** → `Sensor_Encryption.pptx` |
| SC-5 | **Gateway Decryption**             | Title + graph only        | Open envelope → validate → accept                                   | **Built** → `Gateway_Decryption.pptx` |

**Delivery rule (SC-1…SC-5):** each slide is a **separate one-slide PPTX**; on-slide content is **heading + graph only**. Diagrams: `architecture/arch-sc*.html` → `architecture/iot-securegate-sc*.png` on 20×11.25 navy-gradient slides (two-tone Inter Bold title: `#F6F6F6` + `#4596FD`).

Replay cache, deny logs, and auth-status counters stay **spoken or a single footer callout** on SC-3/SC-5 (or move to Intelligent Protection). They are no longer a peer top-level slide.

---

### SC-0 — Security Core (section opener)

**Title:** Security Core

**On-slide (suggested):**

- One line: *How a sensor message is admitted, protected, and accepted*
- Mini agenda strip: Registration → Outer path → Inner path → Encrypt → Decrypt

**Speaker notes:**

- This section is Thức’s Security Core, but told as an end-to-end **message journey**, not four disconnected feature lists.
- Management & Monitoring already showed *who runs what*; here we show *what must pass* before data lands in Kafka / logs.

---

### SC-1 — Device Registration

**Title:** Device Registration

**Format:** Left-to-right or vertical stage list (not a full UI tour).

**Stages to show (from register playbook):**

1. Capacity check (disk / Kafka catalog)
2. MQTT username + password hash
3. Topic ACL (publish/subscribe rights)
4. mTLS client certificate (CA-signed)
5. Envelope secrets + JSON schema on the gateway
6. Kafka topic `sensor.<device_id>` reserved
7. Mosquitto reload → device ready to connect

**On-slide bullets (keep short):**

- Identity: MQTT user + client cert
- Authorization: ACL + reserved Kafka topic
- Crypto material: wrap/mac secrets + schema

**Speaker notes:**

- Registration is **setup**, not the runtime path. Without it, outer admission fails closed.
- Real sensors get a downloadable cert/crypto bundle; lab fakes are app-fed the same classes of material.
- Password + client cert + ACL work **together** (cert does not replace password).

**Sources:** `docs/details.md` Register playbook; `docs/AI-PLATFORM-KNOWLEDGE.md` § register playbook.

---

### SC-2 — Outer Admission Path

**Title:** Outer Admission Path

**Subtitle (optional):** Sensor ↔ Gateway · wire gates before any payload is trusted

**Format:** Horizontal relation graph, Sensor on the left, Gateway/Mosquitto on the right, numbered stages on the link.

**Stages (outer layer, in order):**

| #  | Stage label                                                       | What happens                                                               | Real mechanism                                                                                                                              |
| -- | ----------------------------------------------------------------- | -------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| 01 | **mTLS handshake**                                          | Sensor and broker prove identity with certificates; session keys for MQTTS | MQTTS `:8883`, `require_certificate`, CA-signed client + server certs                                                                   |
| 02 | **Network / firewall rule**                                 | Only expected sensor IPs reach the broker port                             | Host firewall / allow-list posture; Auto-prevent DROP is the *response* face of the same IP gate (detail later in Intelligent Protection) |
| 03 | **Username & password**                                     | Broker authenticates the MQTT user                                         | Mosquitto password file                                                                                                                     |
| 04 | **Topic ACL** (compact on this slide or first step of SC-3) | User may publish only to its registered topics                             | Mosquitto ACL                                                                                                                               |

**Graph intent:** show interaction arrows Sensor ⇄ Gateway for each stage; rejected traffic stops at the failing gate (fail closed).

**Speaker notes:**

- Outer layer answers: *who may open a connection and publish?*
- Recommend drawing **01 mTLS → 02 firewall/IP → 03 password** as the three big nodes; ACL can be a small fourth node or the bridge into SC-3.
- Do not deep-dive envelope crypto here — ciphertext still rides *inside* the TLS session.

**Sources:** `architecture.md` §4–5; Mosquitto MQTTS path in knowledge base.

---

### SC-3 — Inner Processing Path

**Title:** Inner Processing Path

**Subtitle (optional):** Inside the gateway after Mosquitto accepts the publish

**Format:** Vertical pipeline relation graph (matches Metric order: MQTT → Decrypt → … → Kafka).

**Stages:**

| #  | Stage label                         | What happens                                              | Real mechanism                                                         |
| -- | ----------------------------------- | --------------------------------------------------------- | ---------------------------------------------------------------------- |
| 01 | **Deliver to decrypt worker** | Broker hands the message to the agent subscriber          | Decrypt worker MQTTS client on `:8883`                               |
| 02 | **Decrypt / open envelope**   | Pair `env/key` + `env/data`, unwrap CEK, AES-GCM open | `envelope_v1` / decrypt worker (legacy Fernet only if still enabled) |
| 03 | **Structure validation**      | Plaintext must match registered JSON schema               | `schema_validate.py`                                                 |
| 04 | **Topic / sink binding**      | Accepted message maps to the sensor’s storage topic      | Produce `sensor.<device_id>` (+ append `sensor_data.log`)          |
| 05 | **Kafka sink**                | Durable per-sensor topic for consumers / Grafana          | Kafka KRaft INTERNAL `:9092`                                         |

**Fail-closed callout (footer or side note):** decrypt, stamp, day, schema, or pairing failure → deny log · **no** Kafka produce · **no** `sensor_data.log` line.

**Speaker notes:**

- This slide is the **internal** story after outer admission succeeded.
- “Topic sending validation” on-slide = binding to the registered Kafka topic / ACL-allowed MQTT topics already enforced; emphasize that only schema-valid plaintext is sunk.
- Short mention: `msg_id` replay cache and deny counters exist; full monitoring UI stays in Management & Monitoring / Intelligent Protection.

**Sources:** `architecture.md` verification path; `details.md` Runtime path after publish.

---

### SC-4 — Sensor Encryption

**Title:** Sensor Encryption

**Subtitle (optional):** Two layers · one message

**Format:** Packaging / stack diagram (sensor builds outward).

**Layer stack to draw:**

```
Plaintext JSON (schema-checked locally)
        ↓
Layer 2 — Application envelope
   • fresh CEK + nonce + msg_id
   • AES-GCM ciphertext
   • wrapped CEK (v1-psk or v1-ecdhe)
   • HMAC stamp
   • split publish: env/key + env/data
        ↓
Layer 1 — Transport MQTTS (mTLS)
   • whole MQTT publish inside TLS session
        ↓
Wire toward gateway :8883
```

**On-slide emphasis:**

- Two **independent** layers: transport (who) vs envelope (confidentiality after TLS ends)
- Dual MQTT topics: `sensors/{id}/env/key` and `sensors/{id}/env/data`
- Profiles: `v1-psk` (tiny/MCU) · `v1-ecdhe` (ECDH + daily DMEC)

**Speaker notes:**

- Why envelope: after TLS termination on the broker, payload must stay confidential until the decrypt worker opens it.
- Binding stamp ties key half and data half; day window limits stale material.
- Do not walk every crypto primitive on-slide; keep CEK / wrap / stamp / dual-topic as the four labels.

**Sources:** `details.md` Encryption (envelope v1); `architecture.md` §5.

---

### SC-5 — Gateway Decryption

**Title:** Gateway Decryption

**Subtitle (optional):** Open · validate · accept

**Format:** Mirror of SC-4 (unpacking pipeline), intentionally symmetric.

**Stages:**

```
Receive env/key + env/data
        ↓
Pair by (device_id, msg_id)
        ↓
Verify stamps · check day_id window
        ↓
Unwrap CEK (PSK or ECDHE/DMEC)
        ↓
AES-GCM open → plaintext
        ↓
Schema validate
        ↓
Accept → sensor_data.log + Kafka sensor.<device_id>
        (+ shipper → Loki)
```

**On-slide emphasis:**

- Gateway **always decrypts** so it can validate and store
- Fail closed on any open/schema error
- Symmetric twin of Sensor Encryption (reuse colors/icons from SC-4)

**Speaker notes:**

- Pair timeout default ~5s; unpaired halves drop.
- Replay: recent `msg_id` cache (`IOTGW_ENVELOPE_REPLAY_CACHE`).
- Metrics: `iotgw_envelope_messages_total{result="ok|fail"}`.
- Hand-off: accepted plaintext is what Intelligent Protection / Activities can observe.

**Sources:** `details.md` Seal → open flow; decrypt worker modules.

---

### Dropped / relocated from the old Security Core outline

| Old heading                                             | Where it goes now                                                                            |
| ------------------------------------------------------- | -------------------------------------------------------------------------------------------- |
| Device registration and credential management           | **SC-1 Device Registration**                                                           |
| Lightweight mutual authentication and access control    | **SC-2 Outer Admission Path** (mTLS + password + ACL + IP gate)                        |
| Secure MQTT communication and session key establishment | Split: transport session in **SC-2**; app-layer keys in **SC-4 / SC-5**          |
| Replay prevention and authentication status monitoring  | Callouts on **SC-3 / SC-5**; UI counters stay with Monitoring / Intelligent Protection |

---

## Working rules

1. Update this markdown when structure changes.
2. Build **one slide at a time**.
3. Advance only after your **explicit approval**.
4. Keep slides 1–2 intact.
5. Slides 3+ use clean navy gradient backgrounds.
