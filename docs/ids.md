# Gateway IDS

The desktop app installs, controls, and displays an intrusion detector that runs
on each provisioned gateway. It does not run inference or install the IDS
machine-learning packages on the operator's computer. Alerts are records only;
they never block, quarantine, or disable devices (no link to Auto prevent,
firewall, ACL, or device-block actions).

## Architecture and data flow

```text
Sensor MQTT/TLS traffic
        |
        v
iot-gateway-agent.service
  decrypt + validate
  keep sensor_data.log unchanged
  append ids_events.jsonl
        |
        v
iot-gateway-ids.service (own venv, bundled model)
  tail structured JSONL -> features + rules -> ids_alerts.log
        |
        v
agent Loki shipper (job="ids-alerts") -> Loki -> authenticated control API -> Security UI

Security UI -> authenticated control API -> SSH/sudo -> IDS config + systemd unit
```

- Paths: events `/var/lib/iot-gateway-agent/logs/ids_events.jsonl`, alerts
  `/var/lib/iot-gateway-agent/logs/ids_alerts.log`.
- Each event holds only fields the agent actually observed: device ID, topic,
  decrypted payload, gateway receive time, payload size, broker port, and the
  sensor-to-gateway delay when the device timestamp is valid. The legacy
  `sensor_data.log` is plaintext, so IDS never reads it.
- The IDS buffers partial JSONL writes and handles file rotation/truncation.
- The LightGBM model scores a 12-feature vector (order fixed by
  `gateway/ids/models/model_metadata.json`, checked at deploy and startup) over
  a 3-second window; model decisions are smoothed over several windows. Rules
  are separate explainable checks. A missing or unloadable model is an error,
  never a placeholder fallback.
- Alert records keep the source IDS schema (`event_type`, timestamp, severity,
  device, detection/reason, message, score where available).
- `iot-gateway-ids.service` is independent of `iot-gateway-agent`: IDS
  controls never restart MQTT/decrypt/Kafka/metrics, detection continues when
  the desktop app is closed, and the unit is enabled at boot with bounded
  restart throttling.

## Deployment

- The AppImage bundles the IDS source, gateway-only pinned requirements, config
  template, systemd unit, model, scaler, and metadata under `gateway/ids/`.
- Provisioning validates assets, stages and replaces `/opt/iot-gateway-agent/ids`,
  creates/reuses the isolated `/opt/iot-gateway-agent/ids-venv`, installs
  dependencies on the gateway, and verifies model load, feature order, and a
  prediction before reporting success. Any failure is a deployment failure.
- Supported gateways: Linux `x86_64` and `aarch64` with `python3`,
  `python3-venv`, `apt`, and `libgomp1`. 32-bit ARM is unsupported. The pinned
  wheels must exist for the gateway's Python/architecture.
- Re-provisioning is idempotent: config and logs under
  `/var/lib/iot-gateway-agent/` are preserved (supported settings kept; paths
  reset; model pinned to the bundled assets). Existing gateways without IDS show
  **Not installed** until provisioned/updated.

## Using it

1. Register and provision (or update) the gateway in **Gateways**.
2. Open **Security**, select the gateway. Saved enabled state, systemd service
   state, and runtime/model readiness are shown separately.
3. Click **Enable IDS** / **Disable IDS**, adjust supported ML, rule, and
   threshold settings, and apply. Values are validated server-side, config is
   written atomically, and only `iot-gateway-ids.service` is restarted/stopped.
   Success is shown only after the remote operation and a status check succeed.
   Saved sudo credentials are used, or the UI asks for the sudo password.
   Disabling keeps config and alert history.
4. Alerts auto-refresh and can be refreshed manually, filtered by time range,
   severity, and text. Values are rendered as text. No alerts, disabled,
   not installed, unreachable gateway, and Loki failures are distinct states;
   errors are never shown as an empty healthy list.

## Model and tests

The model is an inference-only LightGBM binary classifier (`0` normal,
`1` attack) with 12 ordered features, threshold `0.05`, and scaling disabled.
Live traffic never trains or updates it. Training data, the held-out E2E test,
attack simulation, other IDS test suites, and provenance caveats are in
[`ids-e2e-testing.md`](ids-e2e-testing.md). The offline E2E is not shown in the
app and has not been run locally (LightGBM missing).

## Signals and limitations

- The decrypt worker cannot observe the publisher's source IP, so events omit
  `source_ip`; IP allow-list/expected-IP and cross-IP rules are disabled.
- Node-RED denied-event and HAProxy rules cannot be evaluated; the event stream
  holds only accepted, decrypted messages.
- No Raspberry Pi, ARM wheel install, or real systemd deployment was exercised.
  Verify OS packages, wheels, service health, model startup, and live
  detection quality on each device family. Real-hardware performance is
  unmeasured.
