# Gateway IDS

The IDS is controlled from the desktop app but runs only on the Linux gateway. The Windows `.exe` bundles the trusted IDS source and model for provisioning; it does not install or run the machine-learning dependencies on Windows.

## Data and service flow

1. The gateway decrypt worker validates a sensor message as usual and appends an additional structured record to `/var/lib/iot-gateway-agent/logs/ids_events.jsonl`. The existing `sensor_data.log` format and Kafka path are unchanged.
2. The independent `iot-gateway-ids.service` tails the structured log, groups messages into short device windows, evaluates behavioral rules and the bundled LightGBM model, then writes alert JSONL records to `/var/lib/iot-gateway-agent/logs/ids_alerts.log`.
3. The existing gateway shipper forwards alerts to the operator's Loki instance using `job="ids-alerts"` and a gateway host label.
4. The Security page reads status/configuration through authenticated control-service routes over the existing SSH connection and retrieves alerts from Loki.

Gateway code and model are installed under `/opt/iot-gateway-agent/ids`; inference dependencies live in the isolated `/opt/iot-gateway-agent/ids-venv` built from the gateway's system `python3`. Configuration is `/var/lib/iot-gateway-agent/ids_config.yaml`. Provisioning supports Linux `x86_64` and `aarch64` gateways with Python 3.10 through 3.13. Missing assets, unsupported platforms, dependency failures, or an invalid model stop provisioning with an error.

## Controls and alerts

From **Security → Gateway IDS**, choose a registered gateway to view whether the IDS is installed, whether the model/runtime are ready, the configured enabled flag, and the systemd service state. Enable/disable and supported threshold/rule settings are applied remotely; the config file is installed atomically before changing only the IDS service. Detection continues when the desktop app is closed.

Alerts can be filtered by time range and severity. The page refreshes periodically. A Loki/API failure is shown as an error rather than an empty alert list. An empty list means no alert records were returned for the selected range.

The model's metadata threshold is used when no operator override is configured. The gateway configuration also controls behavioral rules, model enablement, message-rate/clock-skew/connect-publish limits, and alert cooldown. IDS is provisioned disabled.

## Live model test on a Raspberry Pi

Use a dedicated test gateway and
fake sensor: this generates real encrypted MQTT traffic and real IDS alerts.
Synchronize the Windows PC and gateway clocks so the app can distinguish new
alerts from delayed or historical alerts.

1. In Security, enable IDS and ML, disable behavioral rules, and save settings.
   The test requires rules disabled because a rule can otherwise intercept a
   window before the model runs. Record the original settings and restore them
   after the test; disabling rules reduces protection for all gateway devices.
2. In Control Plane, create a dedicated fake sensor. In Simulate use a realistic
   sensor payload accepted by its schema, set the interval to 100 ms, and disable
   all simulated behaviors, including **Alternate encrypted message part order**.
   Apply the settings and start the sensor. Apply may itself start
   the sensor. Use the normal envelope profile.
3. Return to Security, refresh the fake sensor list, select the test sensor,
   and click **Run IDS test**. Keep the page open. The app waits up to 150 seconds
   for a new `ml_anomaly` alert from that sensor, retrieved through Loki. It
   ignores historical alerts and behavioral-rule alerts.
4. Stop the fake sensor in Control Plane and restore the original IDS settings,
   even if the test is inconclusive, an error occurs, or the app is closed.

The approximately 10 messages per second resemble the rate of flood windows in
the training data, but the live encrypted traffic has different topic and
payload features. In particular, normal envelope messages usually yield one
observed topic, whereas the recorded flood often used multiple `/flood/` topics.
The model may miss this realistic traffic even when every component is working.
An observed alert exercises the message and alert path; it does not establish
model accuracy. A missing alert is inconclusive: it may be a model miss or a
failure in message acceptance, IDS processing, or alert delivery. Check gateway
provisioning, sensor connectivity and schema, IDS logs, and Loki delivery.
The app does not automatically stop the sensor or restore settings.

## Safety and limitations

- Alerts are records only. IDS does not block messages, quarantine sensors, alter MQTT ACLs, invoke Auto prevent, or change firewall rules.
- The decrypt worker cannot observe the original MQTT source IP. It does not invent one, and IP-based IDS enforcement remains disabled.
- The IDS receives successfully decrypted and schema-validated messages. It is not a replacement for MQTT authentication, TLS, ACLs, schema validation, or the gateway's existing invalid-message monitoring.
- Only the versioned model bundled with the application is installed. The gateway does not load an operator-supplied pickle/joblib model.
- The operator PC does not need LightGBM, NumPy, or other IDS runtime packages.

## Troubleshooting

1. If status reports **not installed**, provision or update the gateway using the current desktop app bundle.
2. If the model or runtime is not ready, review the provisioning error and gateway package/network availability; provisioning validates model loading and a sample inference.
3. If the service is failed, inspect `systemctl status iot-gateway-ids.service` and the gateway journal. Confirm `/var/lib/iot-gateway-agent/logs/ids_events.jsonl` is being written and the IDS config has not been edited into an invalid state.
4. If the service is running but there are no alerts, check the selected gateway and time range, ensure the alert shipper can reach Loki, and allow enough accepted sensor traffic for the configured windows and smoothing.
