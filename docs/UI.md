# UI guide

How to use each section of IoT Gateway Monitor. System shape: [`architecture.md`](architecture.md). Mechanisms and ports: [`details.md`](details.md).

Left-rail layout after install:

| Section | Items |
|---------|-------|
| **Monitoring** | Gateway Metric · Gateway Activities · Control Plane · Grafana |
| **Gateways** | Registration · Settings · Clean up |
| **Settings** | Remove · Certificates · Admin |

---

## First-run Wizard

Shown when monitoring is not installed yet (`setup_complete` false).

1. Click **Install monitoring** — downloads Loki, Prometheus, and Grafana once and starts them (progress in the wizard). No Docker.
2. When ready, **Open app** enables — opens the left-rail shell (typically Monitoring → Gateway Metric).

LAN setup and gateway install happen later under **Gateways**, not in the wizard.

App data:

| Platform | Path |
|----------|------|
| Windows | `%APPDATA%\IoTGatewayMonitor\` |
| Linux | `~/.local/share/iot-gateway-monitor/` |

**Tip (Windows):** Run the app as Administrator once if you want automatic inbound firewall for Loki `:3100`.

---

## Monitoring

Shared toolbar on Metric / Activities: gateway select, time range (Last 5m–7d), active from→to window, Refresh, optional auto-refresh. Hardware and delay charts use a real clock X-axis (Grafana-style); hover shows time · value.

### Gateway Metric

Host and application health for the selected gateway.

| Area | What you see |
|------|----------------|
| Status cards | Live / scrape health summary |
| Gauges | CPU, RAM, swap |
| Root FS bar | Disk used |
| Hardware charts | CPU %, mem %, load, FS %, net rx/tx, temp |
| Applications | Fixed order: Agent → MQTT → Decrypt → Shipper → Kafka — status, activity, optional CPU/mem |

Empty charts show **No data in range** until Prometheus has scrapes from the agent (`:9139`, job `iot-gateway-agent`).

### Gateway Activities

Message flow and per-sensor Kafka activity.

1. Select a **gateway** (name only in the dropdown).
2. **General** — Total msgs, Msgs/sec, Denied; **Avg messages / sec** chart; transmission delay (Latest + Total, MQTT receive → Kafka produce) with delay chart; **Invalid messages** scrollable table (arrival, reason, IP, sensor, gateway) for TLS/ACL/decrypt/schema denials.
3. **Connected sensors** — table: Device, **Type** (Fake/Real), IP, Kafka topic, Retention, Monitor.
4. **Sensor detail**
   - One sensor → detail panel under the table
   - Several sensors → horizontal name tabs (with Fake/Real badge)
   - Each panel: counters, Kafka topic chart, delay chart, per-sensor **Invalid messages** table
5. **Denied** counts ACL rejects, MQTTS handshake failures (missing/wrong client cert), and decrypt/schema failures. Fake Simulate attacks such as Wrong client certificate or Bad encryption increment Denied and appear in the invalid-message tables.

### Control Plane

Tabs: **Registration | View | Simulate**. Pick a gateway at the top first.

#### Registration — real sensor

1. **Find sensor** — scans neighbors on the gateway (SSH). Pick a host from the list, or **Enter IP manually**.
2. Fill **Device ID**, **Password** (min 8), **Topic RW** / optional **Topic R**.
3. If no CA passphrase is saved yet, use **Generate CA passphrase** (uses Install sudo when available) or enter the Install CA passphrase.
4. **Register** — upserts MQTT user/ACL, Kafka topic, client cert. Download the cert zip once for a real sensor.

#### Registration — Create fake sensor

1. Click **Create fake sensor**.
2. Enter **Device ID**, **Password**, topics only (interval and payload are on Simulate).
3. **Create** — allocates a private IP, registers like a real sensor, feeds certs, leaves `iotgw-fake@` **stopped**.
4. Open **Simulate** to Start and set rate/payload.

Fakes consume one Kafka capacity slot each. Certificates for fakes are managed by the app (no download zip).

#### View

1. Select a registered device.
2. See **Fake** / **Real** badge.
3. Edit IP, topics, monitor flag; password required only when changing IP, topics, or credentials.
4. **Update** appears when the form is dirty.
5. **Delete** requires checking **I am confirming that I want to delete this** (optional: also remove IP from allow-list).
6. **Real only:** Fingerprint, **Re-issue cert**, cert download card.
7. **Fake only:** Auto-renew / Last fed / **Open Simulate** (no Re-issue / fingerprint download).

#### Simulate

Lists `is_fake` devices only.

| Control | Purpose |
|---------|---------|
| Start / Stop | Run or stop `iotgw-fake@` |
| Send interval | Milliseconds between publishes |
| MQTT topic | Publish topic |
| Payload | JSON template (sample: [`samples/fake-sensor-payload.json`](samples/fake-sensor-payload.json)) |
| Behaviors | Lab attack toggles (omit/wrong cert, skip/bad encryption, wrong password/topic, envelope half/stamp/day/schema attacks) |
| Cert status | Feed / expiry line |

TLS attack toggles pause auto-renew until cleared. Apply changes after editing interval/topic/payload/behaviors as prompted by the UI.

**Persistence (Windows):** Form edits are kept when you switch Registration ↔ View ↔ Simulate, and across app restart / reboot. Unapplied drafts live in `%APPDATA%\IoTGatewayMonitor\ui-state.json` (and browser `localStorage`). **Apply** writes interval/topic/payload/behaviors into local `registry.sqlite` first, then pushes them to the gateway unit — so a failed unit restart still leaves the last Apply on this PC. Settings → Remove wipes app data including these files.

### Grafana

Left-nav **Grafana** opens `https://127.0.0.1:9140/` in the **system browser** (not an in-app tab). Trust the cert first under Settings → Certificates if the browser warns.

---

## Gateways

### Registration

Progressive install flow:

1. **Find gateway** — scans the monitoring LAN for open SSH (TCP 22). Ensure a monitoring NIC/IP is available (Registration seeds a default when needed).
2. Click a host in the list.
3. Fill the Install form:

| Field | Meaning |
|-------|---------|
| Host | Address from Find gateway (readonly) |
| User | SSH login name |
| Password | SSH password for install |
| Gateway ID | Name in the app (default `gateway`) |
| Sudo password | Admin password for install; **saved** for fake sensors and cleanup |
| Generate CA passphrase | Default on — creates signing password for this gateway |
| CA passphrase | Manual entry when Generate is off |

4. **Install gateway** — pins host key, installs SSH key, applies firewall when applicable, provisions agent + Mosquitto + Kafka + CA, registers the gateway locally.

Errors surface only on failure.

### Settings

Configure a **registered** gateway:

1. Select gateway.
2. Host/IP is readonly; edit Username; optional Password.
3. **Save** — with a non-empty Password, re-runs fetch/pin/install-key and refreshes saved sudo; otherwise updates settings only.

Use this to backfill sudo for an already-installed gateway before Create fake / Clean up.

### Clean up

Remove **one** gateway agent over SSH. Monitoring (Loki/Prometheus/Grafana) stays on the PC.

1. Select gateway.
2. Password optional if sudo was saved at Install or under Settings.
3. **Remove gateway** — uninstalls agent and tears down fake sensors on that host.

---

## Settings

### Remove

Uninstall the **monitoring panel on this PC**:

- Loki, Prometheus, Grafana
- Local app data (settings, registry, keyring, Chromium profile)
- Registered gateways linked to this panel (SSH uninstall when credentials allow)

Confirm with **Confirm remove**. Returns the app to first-run Wizard mode.

### Certificates

Trust Grafana HTTPS on this PC:

| Action | Purpose |
|--------|---------|
| Download certificate | Save `.crt` for browser/OS trust |
| Regenerate | New self-signed cert; re-download and re-trust |
| Open Grafana | System browser → `https://127.0.0.1:9140/` |
| Retry install | Re-run Grafana ensure if install failed |

**Windows trust tip:** Install Certificate → Current User → **Place all certificates in the following store** → Trusted Root Certification Authorities. Do not use “Automatically select”. Close and reopen the browser, then open Grafana.

**Linux:** Import the `.crt` into browser trust settings, then open Grafana.

### Admin

Maintainer controls behind a local PIN (stored in the OS keyring).

1. **Create PIN** / **Unlock** — non-admin installs never see Code Signing.
2. After unlock: **Code Signing** — detect tools, save signing identity (PFX / GPG; passphrases in keyring), sign build artifacts from a folder.

Passphrases are never written to settings or audit logs.

---

## Common tips

- After Install, CA and sudo secrets live in the keyring; Create fake / Clean up usually need no re-entry.
- Packaged Windows EXE embeds UI at build time — source edits under `apps/desktop/ui` appear only after a new build/restart of the packaged app.
- Shared docs/UI changes ship on the `windows` branch, then `linux` (see root README Branches).
- Deep mechanisms (MQTTS, envelope crypto, Kafka capacity, fake bridge): [`details.md`](details.md).
)
