# Gateway IDS

The IDS is controlled from the desktop app but runs only on the Linux gateway. The Windows `.exe` bundles the trusted IDS source and model for provisioning; it does not install or run the machine-learning dependencies on Windows.

## Data and service flow

1. The gateway decrypt worker validates a sensor message as usual and appends an additional structured record to `/var/lib/iot-gateway-agent/logs/ids_events.jsonl`. The existing `sensor_data.log` format and Kafka path are unchanged.
2. The independent `iot-gateway-ids.service` tails the structured log, groups messages into short device windows, evaluates behavioral rules and the bundled LightGBM model, then writes alert JSONL records to `/var/lib/iot-gateway-agent/logs/ids_alerts.log`.
3. The existing gateway shipper forwards alerts to the operator's Loki instance using `job="ids-alerts"` and a gateway host label.
4. The Security page reads status/configuration through authenticated control-service routes over the existing SSH connection and retrieves alerts from Loki.

Gateway code and model are installed under `/opt/iot-gateway-agent/ids`; inference dependencies live in the isolated `/opt/iot-gateway-agent/ids-venv`. Configuration is `/var/lib/iot-gateway-agent/ids_config.yaml`. Provisioning supports Linux `x86_64` and `aarch64` gateways with Python 3.9 through 3.12. Missing assets, unsupported platforms, dependency failures, or an invalid model stop provisioning with an error.

## Controls and alerts

From **Security → Gateway IDS**, choose a registered gateway to view whether the IDS is installed, whether the model/runtime are ready, the configured enabled flag, and the systemd service state. Enable/disable and supported threshold/rule settings are applied remotely; the config file is installed atomically before changing only the IDS service. Detection continues when the desktop app is closed.

Alerts can be filtered by time range and severity. The page refreshes periodically. A Loki/API failure is shown as an error rather than an empty alert list. An empty list means no alert records were returned for the selected range.

The model's metadata threshold is used when no operator override is configured. The gateway configuration also controls behavioral rules, model enablement, message-rate/clock-skew/connect-publish limits, and alert cooldown. IDS is provisioned disabled.

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
