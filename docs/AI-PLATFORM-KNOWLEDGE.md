# IoT-SecureGate — AI Platform Knowledge Base

> **Purpose.** Single readable reference for writing about the **shared IoT-SecureGate product** (and for extending the code). Grounded in this repository’s source, docs, and UI.
>
> **Writing target:** `thesis-new.tex` (ground-up rewrite).  
> **Reference only:** `thesis.tex` (old draft — reuse facts, packages, screenshots, bibliography; do not copy its “evidence-limited / three separate jobs” posture).
>
> **Companion docs:** [`architecture.md`](architecture.md) · [`details.md`](details.md) · [`UI.md`](UI.md) · root [`README.md`](../README.md)
>
> **Product names:** Academic / platform name **IoT-SecureGate**. Packaged desktop app in this repo: **IoT Gateway Monitor**.

---

## 0. How to use this file

| When you need… | Read |
|----------------|------|
| What the project is (unified platform) | §1 |
| Repository layout | §2 |
| Architecture, ports, data path, crypto | §3 |
| Function-by-function implementation | §4 |
| UI screens and click-paths | §5 |
| Platform modules → code (not people) | §6 |
| Implemented vs planned (honesty) | §7 |
| Screenshots | §8 |
| Guidance for `thesis-new.tex` (whole-system outline) | §9 |
| Glossary | §10 |

**Rules for the new thesis**

1. Write about **IoT-SecureGate as one whole system** (monitoring application + gateway), not as three role-split products or theses.  
2. **Do not** structure chapters around “Security Core / Intelligent Protection / Management & Monitoring” as separate top-level parts. Those names may appear only when useful as informal labels inside a system section; the outline follows architecture and runtimes.  
3. Prefer claims that map to paths under `apps/`, `gateway/agent/`, or `docs/`.  
4. Use `thesis.tex` only as a quarry for metadata, wording snippets, bib entries, and figure ideas.  
5. This is a **system thesis**, not a user manual: explain functions first; UI screenshots are short references afterward.

---

## 1. Project identity — Unified Software Platform: IoT-SecureGate

### 1.1 What the project is

**IoT-SecureGate** is a lightweight security software platform for IoT gateways in edge computing environments. It turns earlier Senior Project research prototypes (scripts, compose stacks, separate tools) into a **single deployable application** that non-technical users can install and operate.

**Intended end-user journey**

1. Run the installer  
2. Open the graphical interface  
3. Configure basic MQTT / gateway settings  
4. Start monitoring / protection services  
5. The platform launches the required local and gateway services automatically  

Users should not need Docker, Python, Linux commands, or source edits for routine use.

**Integrated final package**

- Software installer (Windows and/or Linux)  
- Web-based / desktop GUI  
- Optional ESP32 firmware (if applicable)  
- User manual  
- Technical documentation  
- Complete source code  

### 1.2 Platform organization (one system, two runtimes)

```
                        IoT-SecureGate
                              │
         ┌────────────────────┴────────────────────┐
         │                                         │
 Monitoring application                      Gateway
 (operator PC)                           (edge device)
```

| Runtime | Role in the system |
|---------|-------------------|
| **Monitoring application** | Packaged operator app + control service + local Loki/Prometheus/Grafana: discover/provision gateways, register devices, show metrics and activities, drive day-2 control |
| **Gateway** | `iot-gateway-agent` + Mosquitto MQTTS + Kafka: admit sensors, authenticate/authorize, decrypt/validate, store/ship data, expose metrics, detect and restrict misuse |

**Thesis note:** Describe the **entire system as a whole** along this split (general architecture → monitoring application → gateway). Do **not** divide the document into three parallel “Security Core / Intelligent Protection / Management & Monitoring” role chapters. Security mechanisms (authentication, mTLS, encryption/decryption) belong under the **Gateway** chapter; operator-facing functions belong under **Monitoring Application**.

The team delivers **one integrated software package**, not three independent research folders.

### 1.3 Relation to the Senior Project

The Senior Project supplied gateway, IDS research, and monitoring infrastructure. This project **reuses that base** and shifts the goal to a **user-friendly, installable platform** with a unified GUI and documentation.

### 1.4 What this repository implements

Workspace: `/home/bach/workspace/iot-gateway`  
Shipped UI branding: **IoT Gateway Monitor** (Windows `.exe` / Linux AppImage).

This tree is the **integrated implementation** of IoT-SecureGate as a packaged desktop + edge agent system:

- Strong coverage of **management, monitoring, deployment, and day-2 operations**  
- Substantial **security** (registration, MQTTS, ACL, CA/certs, envelope v1, schema validation)  
- **Protection** hooks (deny watching, invalid-message UI, Auto prevent quarantine, Simulate attacks)  
- Full research-style **LightGBM IDS** as a first-class packaged UI module is **not** present here (see §7); optional Senior Project IDS may be described as related work or future integration without claiming it ships in the current installer

---

## 2. Repository map

| Path | Role |
|------|------|
| `apps/desktop/` | Packaged UI, wizard shell, Windows/Linux packaging |
| `apps/control-service/` | FastAPI control plane, provisioner, telemetry, SSH playbooks, registry |
| `gateway/agent/` | Monolithic gateway agent (systemd + Python) |
| `docs/` | Architecture, details, UI guide, this knowledge file, samples |
| `deploy/templates/prometheus.yml` | Scrape template for agent `:9139/metrics` |
| `assets/docs/` | UI screenshots for manuals / thesis figures |
| `thesis.tex` | **Old draft** — reference only |
| `thesis-new.tex` | **New ground-up thesis** |
| `.github/workflows/desktop-packages.yml` | Builds `.exe` / AppImage → GitHub `desktop-latest` |

**Branches:** `main` (integration), `linux` (AppImage CI), `windows` (`.exe` CI).

**App data on the operator PC**

| OS | Path |
|----|------|
| Linux | `~/.local/share/iot-gateway-monitor/` |
| Windows | `%APPDATA%\IoTGatewayMonitor\` |

Typical contents: settings, `registry.sqlite`, telemetry binaries, Chromium profile, logs, keyring fallback.

---

## 3. Architecture

### 3.1 Two runtimes, one platform

1. **Operator PC — management application**  
   Desktop UI + control service + native Loki (:3100) + Prometheus (:9090) + Grafana HTTPS (:9140).  
   Default path: **no Docker**, **no WSL**.

2. **Gateway device — security & data plane agent**  
   Systemd `iot-gateway-agent` + system Mosquitto MQTTS `:8883` + Kafka KRaft (`:9092` internal / `:9094` external).  
   Optional lab fake sensors on bridge `iotgw-fake` (`10.255.0.0/24`).

**Control plane:** SSH (provision and day-2 playbooks).  
**Data plane:** MQTTS (sensors → broker → decrypt → log/Kafka) + HTTP (metrics scrape, Loki push).

```
Operator PC                         Gateway
───────────                         ───────
UI (:9138) ──► Control (:9137) ──SSH──► Agent (:9139)
   │                                      │
Loki · Prometheus · Grafana               ├── Mosquitto MQTTS :8883
   ▲                                      ├── Decrypt → sensor_data.log → Kafka
   │                                      └── Shipper ─────────────────────┘
   └──────── scrape / push ───────────────┘
Sensors ── MQTTS + envelope ─────────────► Mosquitto
```

### 3.2 Ports

**Operator PC**

| Component | Bind | Notes |
|-----------|------|-------|
| Control service | `127.0.0.1:9137` | FastAPI |
| Wizard / UI | `127.0.0.1:9138` | Static UI + `/api/v1` proxy |
| Loki | `:3100` | Shipper target |
| Prometheus | `:9090` | Scrapes `{gateway_ip}:9139` |
| Grafana | `https://127.0.0.1:9140` | Opens in system browser |

**Gateway**

| Component | Bind | Notes |
|-----------|------|-------|
| Agent HTTP | `:9139` | `/metrics`, `/v1/health`, `/v1/crypto/day/current` |
| Mosquitto MQTTS | `:8883` | Password + client cert |
| Kafka INTERNAL | `127.0.0.1:9092` | Agent produce |
| Kafka EXTERNAL | `{gateway_ip}:9094` | Grafana datasource (trusted LAN) |

### 3.3 Sensor → storage path

```
Sensor ──MQTTS──► Mosquitto :8883
                      │ ACL / password / mTLS
                      ▼
               Decrypt worker (envelope v1 or legacy Fernet)
                      │ schema validate
                      ├─► sensor_data.log ──shipper──► Operator Loki
                      └─► Kafka topic sensor.<device_id>
Prometheus ◄── scrape :9139/metrics ◄── Agent
```

Canonical Metric UI application order: **Agent → MQTT → Decrypt → Shipper → Kafka**.

### 3.4 Encryption layers

| Layer | Mechanism | Answers |
|-------|-----------|---------|
| Transport | MQTTS mTLS + Mosquitto password/ACL | Who may connect / publish |
| Application | Envelope v1 (`v1-psk` / `v1-ecdhe`) | Confidentiality after TLS termination |
| Schema | Registered JSON schema | Message shape after decrypt |
| Day material | DMEC (daily P-256 cert under gateway CA) | Day-scoped wrap for `v1-ecdhe` |

Envelope uses dual MQTT topics `sensors/{id}/env/key` + `.../env/data`, AES-128-GCM content key, HMAC stamp, optional ECDH. Anti-replay cache: `IOTGW_ENVELOPE_REPLAY_CACHE` (default 4096). Legacy Fernet remains accepted until `IOTGW_ENVELOPE_REQUIRE=1`.

Full crypto reference: [`details.md` — Encryption](details.md#encryption-envelope-v1).

### 3.5 Secrets handling

- OS keyring service `iot-gateway-monitor` (file fallback `keyring-fallback.json`)  
  - `ca:{gateway_id}` — CA passphrase  
  - `sudo:{gateway_id}` — gateway sudo for day-2  
  - Admin PIN  
- Secrets are not written to `settings.json` or logs.  
- Provision sudo uses `sudo -S` on SSH stdin.  
- Wizard proxy injects keyring CA/sudo into Control Plane requests when the body omits them.

---

## 4. Detailed implementation map

### 4.1 Desktop shell and packaging

| Concern | Location | Behavior |
|---------|----------|----------|
| Entry / process manager | `apps/desktop/shell/launcher.py` | Starts control + wizard |
| GUI host | `apps/desktop/shell/gui.py`, Tauri `src-tauri/` | Native window; splash → app |
| Wizard HTTP | `apps/desktop/shell/wizard_server.py` | Serves `ui/`, wizard APIs, `/api/v1` proxy |
| Paths / settings | `apps/desktop/shell/paths.py` | App-data root, settings, UI state |
| Discover gateways | `apps/desktop/shell/discover.py` | LAN SSH :22 scan |
| SSH setup | `apps/desktop/shell/ssh_setup.py` | Host-key pin, install operator key |
| Firewall (Windows) | `apps/desktop/shell/firewall_apply.py` | Loki :3100 inbound when elevated |
| Uninstall panel | `apps/desktop/shell/uninstall.py` | Wipe local stack + optional remote gateways |
| Admin auth | `apps/desktop/shell/admin_auth.py` | Local PIN for Code Signing |
| Packaging | `apps/desktop/packaging/` | AppImage / Windows EXE |

First-run monitoring install: `POST /api/wizard/telemetry/ensure` (often background) downloads pinned Loki/Prometheus/Grafana into app data. Pins live in `apps/control-service/telemetry/native_versions.json`.

### 4.2 Control service (FastAPI)

Factory: `apps/control-service/api/app.py` → `create_app()`.

| Module | Responsibility |
|--------|----------------|
| `api/devices.py` | Gateways/devices CRUD, register, fake lifecycle, cert reissue, block/allow, auto-prevent, purge Kafka |
| `api/actions.py` | Rotate server cert / CA |
| `api/query.py` | Loki/Prometheus proxies + summary APIs for Metric/Activities |
| `api/queries.py` | PromQL/LogQL templates |
| `api/fake_cert_renewer.py` | Background mTLS feed for fake sensors |
| `registry/registry.py` | SQLite registry |
| `provisioner/` | SSH provision of agent + Mosquitto + Kafka |
| `telemetry/` | Native binary fetch, lifecycle, readiness, Grafana certs |
| `signing/` | Package signing helpers |
| `actions/playbooks.py` | Day-2 SSH: ACL, certs, Kafka topics, device crypto files |

#### Important APIs

| Method | Path | Effect |
|--------|------|--------|
| GET | `/api/v1/gateways` | List gateways |
| GET | `/api/v1/gateways/{gid}/devices` | List devices |
| POST | `/api/v1/gateways/{gid}/devices/discover` | Neighbor scan |
| GET | `/api/v1/gateways/{gid}/kafka/capacity` | Max sensors from disk budget |
| POST | `/api/v1/gateways/{gid}/devices` | Register real sensor |
| POST | `/api/v1/gateways/{gid}/devices/fake` | Create fake sensor |
| PATCH / DELETE | `.../devices/{id}` | Update / unregister |
| POST | `.../reissue-cert` | New client cert (real) |
| POST | `.../fake/{id}/start\|stop` | Simulator unit |
| POST | `.../control/block\|unblock` | ACL write remove/restore |
| PUT | `.../control/auto-prevent` | Quarantine policy |
| POST | `.../control/auto-prevent/lift` | Clear firewall DROP |
| POST | `.../control/purge-kafka` | Recreate topic |
| GET | `/api/v1/query/summaries/raspi` | Gateway Metric |
| GET | `/api/v1/query/summaries/gateway` | Gateway Activities |

#### Register playbook (real or fake)

Over SSH, typically:

1. Probe disk + Kafka catalog → capacity  
   `max_sensors = floor(total_disk × 0.70 / topic_retention_bytes)`  
2. Upsert Mosquitto password hash + ACL  
3. Sign client cert with gateway CA (download zip for real; app-fed for fake)  
4. Reserve Kafka topic `sensor.<device_id>`  
5. Write device crypto + schema under agent data dir  
6. Reload Mosquitto  
7. For fakes: allocate IP on `iotgw-fake` bridge, install `iotgw-fake@` **stopped**

### 4.3 Gateway agent

Entry: `gateway/agent/iot_gateway_agent/main.py`.

| Module | Function |
|--------|----------|
| `broker.py` | Mosquitto conf / optional child broker; production uses system Mosquitto |
| `decrypt_worker.py` | MQTTS subscribe; envelope pair/open or Fernet; schema; log + Kafka |
| `envelope_v1.py` | Seal/open, stamps, day window, device secrets |
| `day_crypto.py` | Daily Message Encryption Certificate (DMEC) |
| `device_crypto.py` | Per-device secrets and schemas on disk |
| `schema_validate.py` | Compact JSON Schema subset |
| `encrypt.py` / `decrypt.py` | Legacy Fernet |
| `shipper.py` | Tail `sensor_data.log` → Loki |
| `kafka_producer.py` / `kafka_store.py` | Produce and catalog |
| `metrics.py` | Host + application Prometheus metrics |
| `health.py` / `server.py` | HTTP health and crypto day endpoint |
| `denied_watcher.py` | Tail Mosquitto logs → denied counters + deny log |
| `deny_log.py` | Structured invalid messages for Activities UI |
| `auto_prevent.py` | Sliding-window invalid count → firewall DROP helper |
| `mdns.py` | Discovery helper |
| `fake_sensor/simulator.py` | Lab publisher with attack behavior toggles |
| `fake_netns.py` | Netns/bridge for fakes |

**Install layout:** `/opt/iot-gateway-agent`, data `/var/lib/iot-gateway-agent`, Kafka `/opt/kafka`, env `/etc/iot-gateway-agent.env`.

### 4.4 Protection capabilities in this tree

| Capability | Implementation |
|------------|----------------|
| Transport denials (ACL, bad password, missing/wrong cert) | `denied_watcher.py` + Mosquitto logs |
| Decrypt / schema failures | `decrypt_worker.py` → deny log |
| Invalid-message tables + nav badge | Query summaries + `monitoring.js` |
| Auto prevent (IP DROP after N invalids in a window) | Agent `auto_prevent.py` + Control Plane API + Control tab |
| Lab attack simulation | Fake Simulate behavior toggles |
| Prometheus IDS-related counters | `iotgw_ids_detections_total` (deny / optional IDS log regex) |
| Full LightGBM real-time IDS UI module | Not packaged in this repository |

### 4.5 Local registry schema

`registry.sqlite` (`apps/control-service/registry/schema.py`):

- `gateways` — host, ssh_user, install_root, agent_url, fingerprint, monitoring_ip, status  
- `devices` — topics, monitor flag, cert meta, `meta_json` (fake, publish blocked, auto_prevent, …)  
- `imported_allowlist_ips`  
- `state_snapshots`, `audit_log`

---

## 5. UI of the application

Left-rail after install ([`UI.md`](UI.md)):

| Section | Items |
|---------|-------|
| **Monitoring** | Gateway Metric · Gateway Activities · Control Plane · Grafana |
| **Gateways** | Registration · Settings · Clean up |
| **Settings** | Remove · Certificates · Admin |

Sources: `apps/desktop/ui/` (`wizard`, `monitoring`, `gateways`, `settings`, `certificates`, `admin`, `actions`, `app-shell`).

### 5.1 First-run Wizard

- Shown when monitoring is not yet installed.  
- **Install monitoring** downloads and starts Loki, Prometheus, and Grafana → **Open app**.  
- Gateway install is under **Gateways → Registration**, not in the first-run wizard.

### 5.2 Gateway Metric

Host and application health for the selected gateway: status cards, CPU/RAM/swap, disk, hardware charts, applications strip (Agent → MQTT → Decrypt → Shipper → Kafka).  
API: `GET /api/v1/query/summaries/raspi`.

### 5.3 Gateway Activities

Alarm banner and nav badge; totals / msgs/sec / denied; transmission delay; invalid-message table; connected sensors (Fake/Real); per-sensor detail.  
API: `GET /api/v1/query/summaries/gateway`.

### 5.4 Control Plane

Tabs: **Registration | View | Simulate | Control**.

| Tab | Actions |
|-----|---------|
| Registration | Find sensor or enter IP; register real (cert zip); create fake |
| View | Edit topics/IP/monitor; delete; real cert re-issue/download; fake → Simulate |
| Simulate | Start/Stop; interval; topic; payload; attack behaviors; cert feed status |
| Control | Block/Allow publish; Auto prevent; Clear Kafka data |

### 5.5 Grafana

Left-nav opens `https://127.0.0.1:9140/` in the **system browser**. Trust the cert under Settings → Certificates first.

### 5.6 Gateways

| Page | Flow |
|------|------|
| Registration | Find gateway (SSH scan) → credentials / CA → Install gateway (agent + Mosquitto + Kafka) → local registry + keyring |
| Settings | Update SSH credentials for a registered gateway |
| Clean up | Remove one gateway agent over SSH; monitoring stack on the PC remains |

### 5.7 Settings

| Page | Flow |
|------|------|
| Remove | Uninstall local monitoring stack and wipe app data (and remote gateways when possible) |
| Certificates | Download / regenerate Grafana HTTPS certificate |
| Admin | PIN unlock → code signing for distribution builds |

### 5.8 End-user journey mapped to the real UI

| Intended step | Actual UI path |
|---------------|----------------|
| Run installer | `.exe` / AppImage from GitHub `desktop-latest` |
| Open interface | Launch desktop app (wizard on :9138) |
| Configure MQTT / gateway | Gateways → Registration, then Control Plane → Registration |
| Start protection / monitoring | Install monitoring + Install gateway; use Activities / Auto prevent / Control (there is no single global “Start Protection” button — describe the real multi-step flow) |

---

## 6. System capabilities → code

Organize thesis chapters by **system runtime and function**, not by author and not by the old three role labels. Authors belong on the title page as the shared project team.

### 6.1 Monitoring application → code

| Capability | Location |
|------------|----------|
| Operator application | Desktop app + control service |
| Dashboards / summaries | `apps/desktop/ui/monitoring.*`, Control Plane, Gateways |
| System health views | Metric / Activities + Prometheus / Loki / Grafana |
| Gateway provision | Telemetry ensure + Gateways Install provisioner |
| Device registration (operator side) | Control Plane Registration + `actions/playbooks.py` |
| Installer | AppImage / Windows EXE CI |
| Operator click-paths (reference only) | `docs/UI.md` |
| Performance signals | Agent `/metrics`, Activities delay gauges (`iotgw_device_delay_ms*`) |

### 6.2 Gateway security and data path → code

| Capability | Location |
|------------|----------|
| Agent runtime | `gateway/agent/iot_gateway_agent/` |
| Authentication / authorization | Mosquitto password + ACL + mTLS client certs |
| Secure MQTT + envelope | MQTTS `:8883` + envelope v1 (`envelope_v1.py`, decrypt worker) |
| Certificate lifecycle on gateway | CA bootstrap, reissue, FakeCertRenewer |
| Replay resistance | Envelope `msg_id` cache |
| Day / session wrap material | DMEC + PSK wrap KDF with `day_id` |
| Denied / invalid detection | `denied_watcher.py`, decrypt/schema deny path |
| Device restriction | Block publish (ACL) + Auto prevent (firewall DROP) |
| Lab fake sensors | Fake Simulate attack behaviors |
| ML LightGBM IDS + report generator | Not packaged in this tree — describe only if external evidence exists |

---

## 7. Implemented vs planned

| Claim | Status in this repo |
|-------|---------------------|
| Docker-free desktop installer (Win/Linux) | Yes |
| One-click local Loki / Prometheus / Grafana | Yes |
| SSH one-click gateway agent provision | Yes |
| Device register + MQTT user/ACL + mTLS cert | Yes |
| Envelope v1 crypto + schema validation | Yes |
| Kafka per-sensor topics + capacity limit | Yes |
| Fake sensors + Simulate attack behaviors | Yes |
| Metric & Activities dashboards | Yes |
| Manual Block / Allow publish | Yes |
| Auto prevent IP quarantine | Yes |
| Grafana HTTPS local cert download | Yes |
| Admin code signing tab | Yes |
| Full LightGBM real-time IDS module in UI | No (counters / log hooks only) |
| Single “Start Protection” button for everything | No — Wizard + Gateways + Control steps |
| Full backup / restore / update wizard | Limited (Remove wipes; no polished backup wizard) |
| ESP32 firmware tree in this repo | Not present |
| Streamlit control plane (Senior Project) | Replaced by desktop + FastAPI |

**Why `thesis.tex` is a poor base:** It frames the work as screenshot-only and unverified, invents a LightGBM pipeline without grounding in this tree, leaves undefined figure references, and underuses the real architecture docs. `thesis-new.tex` should describe the **shipped integrated platform**, then evaluate with clear measured vs not-yet-measured sections.

---

## 8. Screenshots (`assets/docs/`)

| File | Typical use |
|------|-------------|
| `Download-Start-Up-Screen.png` | First-run / install monitoring |
| `UI-to-find-and-register-gateways.png` | Gateways Registration |
| `UI-after-finishing-register-gateway.png` | Gateway installed |
| `UI-to-configure-registered-gateway.png` | Gateways Settings |
| `UI-to-remove-registered-gateway.png` | Clean up |
| `UI-to-register-sensor-for-gateway.png` | Control Plane Registration |
| `UI-after-successfully-register-fake-sensors.png` | Fake created |
| `UI-to-create-fake-sensors-for-testing.png` | Create fake form |
| `UI-to-view-configurations-from-registered-sensors.png` | View tab |
| `UI-to-simulate-maclious-behavior-for-test-sensor.png` | Simulate behaviors |
| `UI-to-control-registered-sensors.png` | Control tab |
| `UI-for-general-metric-reading-from-gateway.png` | Gateway Metric |
| `UI-for-visualize-activity-metric-from-gateway.png` | Gateway Activities |
| `UI-to-get-cert-for-https-access-to-grafana-dashboard.png` | Certificates |
| `UI-to-remove-monitoring-app.png` / `Panel-to-delete-monitoring-app.png` | Settings Remove |
| `VGU-Logo.png` | Title page |

---

## 9. Guidance for `thesis-new.tex`

1. **Subject:** IoT-SecureGate as **one whole system** (monitoring application + gateway).  
2. **Do not** structure the thesis as three role chapters (Security Core / Intelligent Protection / Management & Monitoring). Team members appear on the title page; the narrative follows the system.  
3. **General architecture** follows §3 and `docs/architecture.md` (two runtimes, control vs data plane, end-to-end path).  
4. **Monitoring application chapter:** architecture; how the app interacts with the gateway (install gateway, onboard sensors/fakes); functions described as workflows.  
5. **Gateway chapter:** architecture; agent and MQTT handling; inbound path; APIs/control interfaces; detection/response. Deep encryption/decryption belongs in its own chapter.  
6. **Encryption and decryption chapter:** transport/mTLS, envelope, encrypt/decrypt workflow, schema validation after decrypt.  
7. **Evaluation** uses runnable procedures on the packaged system (admission, protected transmission, monitoring/detection, resources).  
8. **Mine `thesis.tex` for:** supervisors, student IDs, bibitems — then rewrite; discard its role-split and evidence-hedging posture.  
9. **Do not** claim a full LightGBM IDS UI module unless external evidence exists.

**Canonical outline (matches `thesis-new.tex`):**

1. Introduction — problem, aim (gateway function first; packaging secondary); report organization  
2. Technical background and related work  
3. System requirements — operational context, FR/NFR, scope, threat boundaries  
4. General system architecture — overview diagrams only (top-level, monitoring, gateway, planes, inbound path, protection layers, ports, trust); detail deferred  
5. Monitoring application — architecture; interaction with gateway; functions as workflows  
6. Gateway — architecture; agent + MQTT; inbound path; APIs; detection/response  
7. Encryption and decryption — transport/mTLS, envelope, workflow, schema after decrypt  
8. Evaluation  
9. Conclusion and future work  
10. Appendices as needed (protocols, extra figures)  

---

## 10. Quick glossary

| Term | Meaning |
|------|---------|
| Control service | Local FastAPI on :9137 |
| Wizard | Local UI server on :9138 |
| Agent | `iot-gateway-agent` on the gateway |
| Envelope v1 | Application-layer dual-topic crypto |
| DMEC | Daily Message Encryption Certificate |
| Fake sensor | Lab `iotgw-fake@` unit on private bridge |
| Auto prevent | Firewall DROP after invalid-message threshold |
| registry.sqlite | Local PC gateway/device registry |
| IoT-SecureGate | Unified platform name |
| IoT Gateway Monitor | Packaged desktop application name in this repo |

---

*Update this file when architecture or UI contracts change. Keep it project-centric: one platform, three modules, shared deliverable.*
