---
name: Integrate Gateway IDS
description: "Implement and validate the IDS from the sibling IDS_Edge_Model repository in the iot-gateway desktop app, including gateway deployment, UI controls, live alerts, and tests."
argument-hint: "Optional: specify gateway OS/CPU or IDS behavior constraints"
agent: "agent"
---

# Integrate IDS into the IoT Gateway Monitor app

Implement the IDS integration end to end in the **`iot-gateway` application**. Do not stop at an architecture proposal or checklist: inspect both repositories, make the required code and documentation changes in `iot-gateway`, run relevant tests/build checks, and report any remaining limitation clearly.

## Repository roles and boundaries

Both repositories are sibling directories in the same workspace:

- **Target application to modify:** `/home/thuc/workspace/iot-gateway-thesis/iot-gateway`
- **IDS implementation to inspect and port from:** `/home/thuc/workspace/iot-gateway-thesis/IDS_Edge_Model`
- Relative to the target repository, the IDS source is `../IDS_Edge_Model`.

If these absolute paths differ in the active environment, resolve the two repository roots from the open workspace and confirm their names before proceeding. **Make implementation changes only in `iot-gateway`.** Treat `IDS_Edge_Model` as the reference/source repository; do not modify it.

## User requirements

1. The Linux desktop app must let the operator control IDS for a selected registered gateway.
2. The operator must be able to enable and disable IDS from the app.
3. While enabled, IDS must analyze gateway/device behavior and raise suspicious-behavior alerts that are visible and refresh in the app.
4. IDS detection must continue on the gateway when the desktop app is closed.
5. Alerts are notifications/records only. Do not automatically block or quarantine devices; that is outside this request.

## Recommended architecture

- Keep the Linux AppImage as the **installer, controller, and monitoring UI**. Do not run inference on the operator PC.
- Run the IDS on each gateway as a **separate, independently managed systemd service**, rather than a child of `iot-gateway-agent`. IDS controls/restarts must not restart the MQTT/decrypt agent or interrupt normal gateway traffic.
- Use the existing control-service SSH/provisioning path to install, configure, start, stop, and inspect IDS. Follow existing API authentication, validation, error reporting, sudo, and secret-handling patterns. Do not add an unauthenticated network control endpoint on the gateway.
- Prefer an isolated IDS virtual environment/runtime so the IDS scientific/ML dependencies do not unnecessarily burden or destabilize the existing gateway-agent environment. Verify the actual target OS and supported gateway CPU architectures before choosing/installing wheels.
- Integrate the existing Security UI concepts from the source project, adapting them to the target app's navigation, styling, API, and test conventions. Show the selected gateway's **configured state and actual runtime health** (enabled/disabled, running/stopped/failed, model/runtime readiness where practical), not just the saved config.
- Surface structured alerts through the app's existing Loki/query infrastructure. Add periodic alert refresh so new detections appear without manual refresh; surface API/service errors rather than displaying a healthy or empty success state when data cannot be fetched.

## Source IDS to inspect and port

Read and understand the implementation in `../IDS_Edge_Model` before editing, especially:

- `gateway/ids/ids_gateway/` — capture, feature extraction, behavioral rules, model inference, alert generation.
- `gateway/ids/models/` — `ids_model.joblib`, `feature_scaler.joblib`, and `model_metadata.json`.
- `gateway/ids/configs/ids_config.yaml` and `gateway/ids/BEHAVIORAL_RULES.md`.
- `gateway/agent/iot_gateway_agent/ids_runtime.py` and its agent integration.
- `gateway/agent/requirements.txt`.
- `apps/control-service/provisioner/agent_install.py` and IDS deployment tests.
- `apps/control-service/api/ids.py` and IDS API tests.
- `apps/desktop/ui/security.html`, `security.js`, and related styles/navigation.
- Source `README.md` and relevant IDS tests/docs.

Port the smallest coherent set of implementation files/assets necessary. Preserve the existing algorithm, feature order, model metadata/default threshold, rule behavior, and alert schema unless a compatibility defect requires a change. Do not replace the provided model with a placeholder or silently claim inference works if model loading fails.

## Critical integration requirement: input compatibility

The target app's gateway decrypt worker currently writes timestamp-prefixed plaintext lines to its sensor log. The source IDS capture expects structured JSONL event records (for example event type, device ID, topic, payload, timestamps, and source IP). Do **not** point the IDS at an incompatible log and assume it works.

Implement and test a reliable structured IDS input path from the target gateway agent to the IDS. Keep the existing sensor log behavior compatible with existing consumers; use a separate structured IDS event log/stream or another explicitly compatible interface. Include only fields actually available and valid. In particular:

- Confirm how device ID, topic, payload, gateway receive time, and delay are produced in the target agent.
- Do not invent or mislabel the sensor source IP. If the target agent cannot reliably obtain it, correlate it from a trustworthy existing source if feasible; otherwise make IP-dependent rules explicitly unavailable/disabled and document the limitation.
- Ensure log rotation/truncation and partial writes do not cause dropped, malformed, or repeatedly reprocessed events.
- Keep the IDS inference feature vector consistent with the bundled model's exact metadata.

## Deployment and operator controls

- Extend AppImage resource packaging and the existing gateway provisioner so a fresh install uploads the IDS runtime, model assets, configuration, and separate service unit.
- Install dependencies on the gateway, not the operator PC. Surface actionable deployment errors (including unsupported architecture or dependency installation failure); do not report success when the service or model is missing.
- Make provisioning/re-provisioning idempotent and safe for already-installed gateways. Define how upgrades replace IDS files/config without deleting user data or secrets. Existing gateways without IDS should receive a clear “not installed—provision/update gateway” state.
- Add a secure config/control API that supports reading IDS config/status and changing enabled state plus the existing supported rule/ML settings. Validate numeric bounds and accepted values server-side. Save config atomically and restart/stop/start only the IDS service as appropriate.
- The UI must make enable/disable explicit, prevent duplicate submissions, show success only after the remote operation is confirmed, and show useful errors when SSH, sudo, API, or IDS runtime operations fail.
- Ensure gateway-agent or IDS shutdown/restart does not leave orphan detector processes. Service restart policies should not create rapid crash loops.
- Keep alert delivery separate from blocking. Do not wire IDS alerts to Auto prevent, firewall, ACL, or device-block actions.

## Alert UI

Provide a usable Security/IDS area in the target desktop app:

- Select a registered gateway and configure/control its IDS.
- Show IDS enabled state and live service/runtime health.
- Display recent alerts with at least timestamp, severity, device, detection/reason, message, and model score when present.
- Refresh alerts automatically at a reasonable interval and provide a manual refresh.
- Handle no alerts distinctly from IDS unavailable, not installed, disabled, or unreachable.
- Avoid unsafe HTML rendering of gateway-controlled alert values; escape/render as text.
- Retain existing alert filtering/export/review behavior only where it fits target app conventions; do not introduce unnecessary features.

## Correctness, security, and quality requirements

- Inspect the target repository's current implementation and worktree before editing. Preserve unrelated user changes and do not overwrite/delete generated or user data.
- Follow target repository patterns for Python, JavaScript, API schemas, config, UI navigation, tests, and documentation.
- Use structured/atomic config writes and explicit errors. Never log passwords, tokens, private keys, or full secret-bearing request bodies.
- Treat bundled `joblib` model files as trusted, versioned application assets; do not load user-uploaded/untrusted pickle/joblib files.
- Do not add automatic device blocking, Docker requirements for the packaged app, or dependencies to the desktop runtime when they only belong on gateways.
- Add focused tests for model/runtime/config behavior, structured input compatibility, provisioner file/dependency/service installation, IDS API behavior, UI control/refresh/error states, and no unintended gateway-agent restart.
- Update directly related documentation: architecture/data flow, install/update behavior, supported gateway architectures/dependencies, IDS controls/status, alert semantics, and known unavailable signals.

## Required execution sequence

1. Inspect both repositories and identify the target app's actual entry points, provisioning lifecycle, API authentication, gateway log schema, alert shipping/query path, UI navigation, tests, and current worktree changes.
2. Compare source IDS assumptions to the target gateway and write down any compatibility gaps before implementing.
3. Port and integrate the IDS into `iot-gateway`; do not merely copy the source tree or add a plan file.
4. Add/update tests and documentation along with the implementation.
5. Run the smallest relevant test suites first, then any available type/build/package checks covering changed surfaces. Fix failures caused by the changes. If a hardware/architecture check cannot be run locally, state exactly what remains to be verified.
6. Summarize changed files, behavior, test results, deployment steps for a new gateway and an existing gateway, and any remaining limitations.

## Acceptance criteria

- A clean Linux AppImage build includes all files required by the provisioner to deploy the IDS, without bundling the gateway ML runtime as a desktop inference service.
- Provisioning installs a usable IDS service and its model on a supported gateway; missing assets/dependencies or failed model startup are reported as failures.
- The IDS consumes target-app gateway events using a tested, compatible structured input path and emits the source IDS alert format to the configured alert log.
- The desktop app can enable and disable IDS for a selected gateway without restarting the MQTT/decrypt gateway agent.
- The app distinguishes enabled configuration from actual service health and displays newly generated alerts automatically while open.
- Existing gateway/decrypt/monitoring behavior is preserved; IDS alerts do not trigger device blocking.
- Focused tests pass, relevant docs are updated, and any unverified Raspberry Pi/ARM/Linux packaging requirement is explicitly identified.
