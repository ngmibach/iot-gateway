# Gateway IDS

The Security page controls and monitors a detector running on each provisioned
gateway. The desktop app is its installer, controller, and alert viewer; it
does not run IDS inference on the operator PC.

## Runtime and deployment

- The AppImage bundles the IDS source, pinned gateway-only requirements, YAML
  configuration template, systemd unit, model, scaler, and model metadata under
  `gateway/ids/`. The desktop Python environment does not install the IDS ML
  dependencies.
- Gateway provisioning validates the assets, stages and replaces the versioned
  `/opt/iot-gateway-agent/ids` tree, creates or reuses the isolated
  `/opt/iot-gateway-agent/ids-venv`, installs the IDS dependencies on the
  gateway, and verifies model loading, feature order, and a prediction before
  reporting success.
- Supported gateway targets are Linux `x86_64` and 64-bit ARM (`aarch64`) with
  `python3`, `python3-venv`, `apt`, and `libgomp1`. The pinned Python
  dependencies must have wheels/build support for the gateway's Python and
  architecture; dependency or model validation failures are reported as
  deployment failures. 32-bit ARM is not supported. The desktop Linux AppImage
  is built for `x86_64`.
- Detection runs as the independent `iot-gateway-ids.service`, with an
  isolated venv and bundled, versioned model assets. It is not a child of
  `iot-gateway-agent`; stopping or restarting IDS does not restart the MQTT,
  decrypt, Kafka, or metrics agent. The unit is enabled at boot and has bounded
  restart throttling. Closing the desktop app does not stop gateway detection.
- Re-provisioning stages new runtime files before replacing the old IDS code.
  The operator config and logs remain under `/var/lib/iot-gateway-agent/` and
  are not deleted by the IDS upgrade. Config preparation preserves supported
  settings while resetting input/output paths and pinning the model to bundled
  assets. Disabling IDS leaves its config and alert history in place.
- Existing gateways without the unit/config show **Not installed** and need a
  provision/update operation before IDS controls are available.

## Event and alert data flow

After successful decrypt/schema handling, the gateway agent continues to append
the existing timestamp-prefixed plaintext to `sensor_data.log` unchanged. It
also appends one JSONL record to
`/var/lib/iot-gateway-agent/logs/ids_events.jsonl` with the known device ID,
MQTT topic, decrypted payload, gateway receive timestamp, payload byte size,
and broker port. When the payload has a valid device timestamp, its
sensor-to-gateway delay is written in seconds. The agent's Kafka processing
delay metric is not used as sensor delay.

The IDS tails this separate structured file, buffering partial JSONL writes
and detecting file replacement/truncation. It never treats the legacy
`sensor_data.log` as JSON. Model feature columns and their order must match
`model_metadata.json`; the bundled model/scaler are checked at deployment and
again at detector startup. A missing, incompatible, or unloadable model is an
error, not a fallback to a placeholder.

The detector appends JSONL records to
`/var/lib/iot-gateway-agent/logs/ids_alerts.log`. Each record retains the IDS
alert fields (`event_type`, timestamp, severity, device, detection/reason,
message, score and score type where available). The gateway agent ships these
records to Loki with `job="ids-alerts"` and the registered gateway host label.
The authenticated control API queries that stream; the Security page refreshes
it periodically and also supports manual refresh, time range, severity, and
text search. Gateway-controlled alert values are displayed as text.

## Controls and status

The Security page shows saved enabled state separately from systemd service
state and the presence of the runtime/model assets. The control API reads and
updates configuration over the existing authenticated SSH path. Server-side
validation enforces accepted settings and numeric bounds; config replacement
is atomic. Enable/reconfigure restarts only `iot-gateway-ids.service`; disable
stops and disables only that unit. The UI reports success only after the
remote operation and status check succeed. SSH, sudo, service, runtime, and
Loki query failures are shown as errors rather than an empty healthy result.

IDS alerts are records/notifications only. No IDS alert is connected to
Auto prevent, firewall, ACL, quarantine, or device-block actions.

## Signals and limitations

- The decrypt worker does not observe the MQTT publisher's source IP, so IDS
  events deliberately omit `source_ip`; the detector never fabricates it.
  IP allow-list and expected-source-IP checks are disabled, and accepted-event
  cross-IP identity checks are unavailable. Mosquitto connection logs may
  still provide source-IP-based connection statistics for the source IDS
  rules that consume them.
- This gateway does not produce the source project's Node-RED denied-event
  records or HAProxy log stream. Rules that require those inputs, such as
  denied-payload ratios/storms or HAProxy TLS-failure counts, cannot be
  evaluated from the installed data path. The current structured event stream
  contains successfully decrypted/accepted sensor messages.
- A source IP cannot be displayed as part of an accepted-message alert unless
  a future, trustworthy correlation path is implemented.
- No Raspberry Pi hardware/systemd deployment or `aarch64` wheel installation
  was exercised in this development environment. The local host is Linux
  `x86_64`; gateway architecture, OS package availability, and model startup
  must still be verified on each supported device family.
