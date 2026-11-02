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

## Model and training provenance

The model is an inference-only LightGBM binary classifier (`0` normal,
`1` attack) with threshold `0.05` and scaling disabled. Features cover message
volume, topic diversity/flood ratio, payload-size, inter-arrival and delay
statistics, and attack-blob ratio. `process_path_ratio` is constant in the
dataset and not shipped. Live traffic never trains or updates the model.

Supplied research materials (not deployed; kept in a separate
`iot-gateway-submit` tree): 16 labeled sessions, `prepare_ids_dataset.py`
(3-second windows grouped by session/source IP/device; attack=1, benign and
recovery=0), 2,577 windows (263 attack, 2,314 non-attack), and
`train_ids_model.py` (LightGBM, 300 estimators, lr 0.05, 31 leaves, seed 42,
`session_id` group split, threshold swept 0.05-0.95 on validation for 2% target
FPR). Bundled split: 834 train / 1,227 validation / 516 test rows.

Caveats to resolve before claiming reproducible retraining:

- Manifest `label_attack_threshold: 0.34` vs. the script's rule (window is
  attack if at least half of messages are in the attack phase).
- The trainer uses inverse-class-frequency weights; metadata describes a
  `train_weight_hint` and `source_ip`/`device_id` group weighting the trainer
  does not produce.
- The supplied tree's edited metadata has test counts inconsistent with its
  confusion matrix; the E2E checks the bundled model against the **bundled**
  metadata.
- Training/runtime feature differences: training `payload_len` uses the full raw
  JSON line, runtime uses the payload object; inter-arrival calculation also
  differs; and the runtime polls about every second and clears its buffer, so it
  can score smaller windows than the 3-second training windows. Live accuracy may
  differ from the held-out numbers.

## Tests

Offline model E2E (needs the IDS runtime dependencies and `pytest`; no broker,
gateway, or systemd):

```bash
PYTHONPATH=gateway/ids pytest -q gateway/ids/tests/e2e/test_model_pipeline.py
```

1. **Training metadata contract:** task, attack label, threshold, feature order,
   group-split fields, disjoint sessions, row counts, weights declaration,
   disabled scaler.
2. **Held-out evaluation:** scores
   [`model_heldout_test.csv`](../gateway/ids/tests/fixtures/model_heldout_test.csv)
   (516 windows from `heavy_attack_1`, `heavy_attack_2`, `light_attack_2`,
   `sensor1_benign_03`; 462 non-attack, 54 attack; no IPs/devices; session IDs
   never used as features) with the bundled model at the metadata threshold and
   compares confusion matrix, precision, recall, FPR, and FNR to the metadata.
3. **Runtime input path:** writes normal and synthetic attack-like JSONL
   (flood topics, short inter-arrival, `debug.attack_blob`) through
   `SensorLogCapture`, features, and inference. This is a pipeline smoke test
   only; real attack windows are heavier (about 38 messages per 3 s, ~2.6 KB
   payloads). It does not require every event to be flagged and is not an
   accuracy benchmark.

Other suites:

| Suite | Purpose |
|---|---|
| `gateway/ids/tests/test_model_assets.py` | Model load, feature order, probability output. |
| `gateway/ids/tests/test_structured_input.py` | Partial writes, rotation/truncation, no fabricated source IP, config migration. |
| `apps/control-service/tests/test_ids_api.py` | Auth, validation, IDS-only service ops, Loki filtering. |
| `apps/control-service/provisioner/tests/test_provisioner.py` | Missing assets, unsupported arch, dependency errors, separate service install. |
| `gateway/agent/tests/test_decrypt_worker.py` | Structured events with legacy log preserved. |
| `gateway/agent/tests/test_shipper.py` | Alert shipping once across partial writes/rotation. |
| `apps/desktop/tests/security-ui.test.cjs` | Control/refresh/error states, safe rendering. |

The offline E2E is not shown in the app (the Security page shows live alerts
only) and has not been executed in the development environment (LightGBM was
not installed there).

## Signals and limitations

- The decrypt worker cannot observe the publisher's source IP, so events omit
  `source_ip`; IP allow-list/expected-IP and cross-IP rules are disabled.
- Node-RED denied-event and HAProxy rules cannot be evaluated; the event stream
  holds only accepted, decrypted messages.
- No Raspberry Pi, ARM wheel install, or real systemd deployment was exercised.
  Verify OS packages, wheels, service health, model startup, and live
  detection quality on each device family. Real-hardware performance is
  unmeasured.
