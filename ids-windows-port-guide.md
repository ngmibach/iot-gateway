# Porting the gateway IDS to the Windows desktop app

Purpose: a work specification for GitHub Copilot (or any engineer) to bring the
IDS integration, already built and validated on the **Linux** app, to the
**Windows** app. It records what was built and why, the architecture, the exact
file inventory, a verified dry-run of the port, the Windows-specific risks, and
a step-by-step plan with acceptance checks. Companion docs:
[`ids.md`](ids.md) (feature reference), [`ids-e2e-testing.md`](ids-e2e-testing.md)
(model/tests), [`ids-report-guide.md`](ids-report-guide.md) (report facts).

## 1. Key insight: what "Windows version" means

The IDS never runs on the operator PC. It runs on the **gateway**, which is a
Linux machine (Raspberry Pi or x86_64) in both app flavors. The Windows
`IoTGatewayMonitor.exe` and the Linux AppImage are the same Python
(control-service + wizard shell) and HTML/JS UI code, packaged differently:

| | Linux app (done) | Windows app (to do) |
|---|---|---|
| Branch | `linux` / working branch `linux_test` | `windows` |
| Package | AppImage (`apps/desktop/packaging/build_linux_appimage.sh`) | PyInstaller onefile `.exe` (`build_windows.sh`, CI job `windows-exe` on `windows-latest`) |
| App data | `~/.local/share/iot-gateway-monitor/` | `%APPDATA%\IoTGatewayMonitor\` |
| Gateway-side IDS | Linux systemd service, isolated venv | **Identical, unchanged** |
| Gateway SSH/sudo | Paramiko + keyring | Paramiko + Windows Credential Manager (via `shell/keyring_store.py`) |

So the port is mainly: (1) bring the same code changes onto the `windows`
branch, (2) make sure packaging ships the IDS assets inside the `.exe`,
(3) remove Windows-specific hazards (line endings, text-mode temp files,
tests that assume POSIX), (4) update docs, (5) verify. Do **not** write a
Windows-native IDS, do not run inference on the PC, and do not install Python ML
packages on Windows.

## 2. Requirements (unchanged from the Linux task)

1. Operator controls IDS for a selected registered gateway from the app.
2. Enable and disable IDS from the app.
3. While enabled, IDS analyzes gateway/device behavior and raises alerts that
   are visible and auto-refresh.
4. Detection continues on the gateway when the app is closed.
5. Alerts are records/notifications only. No automatic blocking, quarantine,
   firewall, ACL, or Auto-prevent linkage.

Constraints: no unauthenticated gateway endpoint; reuse existing SSH/sudo/token
patterns; never log passwords/tokens/keys; bundled `joblib` model is a trusted
versioned asset (never load user-supplied pickle/joblib); do not modify
`IDS_Edge_Model` (reference source repo) or `iot-gateway-submit` (training data).

## 3. Architecture

```text
Sensor MQTT/TLS -> iot-gateway-agent.service (gateway)
                     decrypt + validate
                     sensor_data.log          (legacy plaintext, unchanged)
                     ids_events.jsonl         (NEW structured events)
                          |
                          v
                   iot-gateway-ids.service    (NEW, independent systemd unit)
                     tail JSONL -> 3 s window features
                     LightGBM + behavioral rules
                     ids_alerts.log (JSONL)
                          |
                          v
        agent Loki shipper (job="ids-alerts") -> Loki (on operator PC)
                          |
                          v
        control-service API (token-authenticated) -> Security page

Security page -> wizard_server (injects sudo password) -> control-service API
   -> SSH/sudo -> IDS config (atomic) + systemctl on iot-gateway-ids only
```

Layers: (1) desktop UI, (2) wizard server and control-service API, (3)
provisioner (SSH install), (4) gateway agent (event producer, alert shipper),
(5) IDS service, (6) Loki as alert store.

Gateway paths: events `/var/lib/iot-gateway-agent/logs/ids_events.jsonl`; alerts
`/var/lib/iot-gateway-agent/logs/ids_alerts.log`; config
`/var/lib/iot-gateway-agent/ids_config.yaml`; code `/opt/iot-gateway-agent/ids`;
venv `/opt/iot-gateway-agent/ids-venv`; unit
`/etc/systemd/system/iot-gateway-ids.service`.

### Design decisions (keep all of them)

| Decision | Why |
|---|---|
| Separate systemd service, not a child of `iot-gateway-agent` | IDS enable/disable/restart must never restart MQTT/decrypt/Kafka/metrics; no orphan processes. Unit: `Restart=on-failure`, `RestartSec=10`, `StartLimitBurst=5` per 300 s (no crash loops). |
| Isolated venv `ids-venv` | ML dependencies must not destabilize the agent environment. |
| Dependencies installed on the gateway at provision time | Desktop never carries numpy/scikit-learn/LightGBM. |
| Control only through the authenticated control-service over existing SSH | No open network control port on the gateway. |
| Separate structured event log | Legacy `sensor_data.log` is timestamp-prefixed plaintext, not the JSONL the source IDS parses. It stays untouched for existing consumers. |
| Source IP never invented | The decrypt worker cannot see the MQTT publisher IP; IP-dependent rules are disabled (`enforce_allowed_ips: false`). |
| Alerts shipped via existing Loki path | Reuses query infrastructure and gateway labeling. |
| Alerts never trigger blocking | Explicit requirement. |

## 4. What was implemented (full inventory)

All paths relative to the repo root. Source of truth for the Linux
implementation: commit `bdaf662` ("Add IDS into UI app") plus the uncommitted E2E
test/docs work described in section 8.

### 4.1 Gateway IDS runtime — `gateway/ids/` (new, gateway-only)

Ported from `IDS_Edge_Model/gateway/ids/` with adaptations.

- `ids_gateway/`: `log_capture.py` (structured JSONL tailer: buffers partial
  lines, handles rotation/truncation, never re-reads processed bytes),
  `features.py` (12 model features, fixed order), `model.py` (loads bundled
  LightGBM; fails loudly, no placeholder), `rules.py` (behavioral rules),
  `alerts.py` (alert schema: `event_type`, timestamp, severity, device,
  detection/reason, message, score, score type), `detector.py`, `main.py`,
  `gateway_state.py`, `install_config.py` (provision-time config prep that
  preserves operator settings but resets paths and pins the bundled model),
  `config.py`, `records.py`, `utils.py`.
- `models/ids_model.joblib`, `feature_scaler.joblib`, `model_metadata.json`
  (binary assets; copied verbatim; threshold 0.05; scaler disabled).
- `configs/ids_config.yaml` (3 s windows, 1 s loop, `capture_type: sensor_log`
  reading `ids_events.jsonl`, smoothing: 6-window aggregation, min 4 windows,
  min 3 attack windows, vote ratio 0.60, average score 0.68; rules enabled;
  `enforce_allowed_ips: false`).
- `requirements-runtime.txt` (pinned: numpy 1.26.4, scikit-learn 1.5.2, scipy
  1.13.1, joblib 1.4.2, pyyaml 6.0.2, paho-mqtt 2.1.0, psutil 6.1.0, lightgbm
  4.5.0, pandas 2.2.2).
- `iot-gateway-ids.service`, `BEHAVIORAL_RULES.md`.

### 4.2 Gateway agent — `gateway/agent/iot_gateway_agent/`

- `decrypt_worker.py`: after decrypt/validation, still writes the legacy
  `sensor_data.log` line unchanged, and additionally appends one JSONL record to
  `ids_events.jsonl`: device ID, MQTT topic, decrypted payload, gateway receive
  time, payload byte size, broker port, and sensor-to-gateway delay (seconds)
  only when the device timestamp is valid. Kafka processing delay is **not**
  used as sensor delay. No `source_ip`.
- `shipper.py`: ships `ids_alerts.log` to Loki with `job="ids-alerts"` and the
  gateway host label, tolerant of partial writes, rotation, truncation; each
  alert shipped once.
- `main.py`: wires the IDS log into the shipper; does **not** pass IDS log paths
  to `DeniedWatcher` (avoids double-handling alert counters).

### 4.3 Provisioner — `apps/control-service/provisioner/agent_install.py`

- Validates that all IDS assets exist in the bundle (`ids_gateway/`, model,
  scaler, metadata, config, requirements, unit); missing assets are an error
  naming the missing paths.
- Uploads to a staging dir `/opt/iot-gateway-agent/.ids-stage-<uuid>`, then
  swaps into `/opt/iot-gateway-agent/ids` with rollback of the old tree on
  failure (idempotent, safe for re-provisioning).
- `_ensure_ids_runtime`: detects OS/CPU/Python; requires Linux and `x86_64` or
  `aarch64` (32-bit ARM rejected with an actionable message); installs
  `libgomp1` via apt; creates/reuses `ids-venv`; `pip install -r
  requirements-runtime.txt`; then runs a gateway-side check that the model
  loads, feature order matches the runtime, and a prediction works. Any failure
  aborts and is reported — never a success without model/service.
- `_prepare_ids_config`: runs `ids_gateway.install_config` to create or migrate
  `ids_config.yaml` while preserving supported operator settings.
- `_install_ids_service`: installs the unit, enables/starts or leaves stopped per
  the config's enabled flag. Config and logs under `/var/lib/iot-gateway-agent/`
  are never deleted by upgrades.
- Tests: `provisioner/tests/test_provisioner.py` (missing assets, unsupported
  architecture, dependency failure, separate service install, agent not
  restarted by IDS operations).

### 4.4 Control-service API — `apps/control-service/api/ids.py`, `app.py`

Router is mounted with `require_token` (existing bearer authentication).

- `GET /gateways/{id}/ids/config`, `GET /gateways/{id}/ids/status`,
  `POST /gateways/{id}/ids/config`, `GET /ids/alerts`.
- `status` reports separately: `installed`, `configured_enabled`,
  `service_state` (`not_installed|running|stopped|failed`), `active_state`,
  `sub_state`, `result`, `model_ready`, `runtime_ready`, and current config.
  Not installed = unit or config file missing -> 409 on config read with message
  "provision or update the gateway first".
- `POST config` (pydantic validation, server-side bounds): `enabled`,
  `rules_enabled`, `ml_enabled`, `threshold` 0..1, `max_message_rate_per_sec`
  (0,1000], `max_clock_skew_seconds` 0..3600, `max_connect_publish_ratio`
  (0,1000], `alert_cooldown_seconds` 0..86400, `sudo_password`. Writes YAML to a
  remote temp file, `install`s it next to the target, atomically `mv`s it, then
  `systemctl enable+restart` (enable) or `disable --now` (disable) on
  `iot-gateway-ids.service` only; re-reads status and returns 502 if it asked
  for enabled but the service/model is not running (or disabled but still
  running). Writes an audit record. Errors pass through `sanitize_user_error`.
- `GET /ids/alerts`: LogQL `{job="ids-alerts"} | json | event_type="ids_alert"`
  (optionally filtered by gateway host), range in `15m|1h|6h|24h|7d`, severity
  filter, limit up to 2000; returns an id per alert, sorted newest first.
  Loki failure raises an error (never an empty success).

### 4.5 Desktop shell and UI — `apps/desktop/`

- `shell/wizard_server.py`: `_should_inject_sudo` returns true for
  `POST .../ids/config` so the stored gateway sudo password is injected
  (test in `tests/test_ca_inject.py`).
- `ui/app-shell.js`: adds the **Security** nav item (`security.html`) and active
  page detection.
- `ui/security.html|js|css` (new): gateway selector; separate display of
  configured state, service state, model/runtime readiness; explicit Enable/
  Disable buttons with duplicate-submit prevention; success shown only after the
  API confirms; settings form; alert table (time, severity, device, reason,
  message, score) with range/severity/text filters; refresh every `POLL_MS =
  15000` plus manual refresh; distinct states for no alerts, disabled, not
  installed, unreachable, Loki error; all gateway-controlled values rendered
  with text APIs (no unsafe HTML).
- Tests: `tests/security-ui.test.cjs` (Node; control/refresh/error/safe
  rendering).

### 4.6 Docs

`README.md` docs table, `docs/architecture.md`, `docs/details.md`, `docs/UI.md`
(IDS sections), and `docs/ids.md`, `docs/ids-e2e-testing.md`,
`docs/ids-report-guide.md`.

### 4.7 Offline model E2E (uncommitted when this was written)

`gateway/ids/tests/e2e/test_model_pipeline.py` and fixture
`gateway/ids/tests/fixtures/model_heldout_test.csv` (516 held-out windows,
462 benign / 54 attack, from the supplied training data's test sessions).
Described in [`ids-e2e-testing.md`](ids-e2e-testing.md). It has **not** been run
locally (LightGBM absent in the dev environment).

### 4.8 Other validated results (Linux)

- 61 focused Python tests and 2 Node UI tests passed; a temporary AppImage built
  and extracted successfully with IDS assets present and no LightGBM in the
  desktop bundle; the permanent AppImage was then rebuilt and replaced.
- Two pre-existing unrelated failures were excluded: a Kafka layout fixture test
  and a fake-device "stopped" message assertion.

## 5. Verified dry run of the port

A throwaway worktree of `origin/windows` had `bdaf662` cherry-picked with
`--no-commit` (then aborted and removed; no repo state changed):

- **All code applied cleanly** (including `agent_install.py` and
  `test_provisioner.py`, which also differ on `windows`).
- **Only three files conflicted, all docs:** `README.md`, `docs/architecture.md`,
  `docs/details.md`. Resolve by keeping the Windows branch's text and adding the
  IDS sections/rows.
- `origin/windows` differs from the Linux base in: `provisioner/ssh.py` (a
  wall-clock `run()` timeout loop that helps long `pip install` steps),
  `kafka_install.py`, `telemetry/*`, `src-tauri/src/lib.rs`, an extra
  `docs/AI-PLATFORM-KNOWLEDGE.md`, and different `docs/architecture.md` /
  `details.md`. CI workflow files live on `main`.
- Repo convention (README "Branches"): shared docs/UI changes ship on `windows`
  then `linux` as a pair (`feat(windows): ...` / `feat(linux): ...`), and
  `main` is the source of truth mirrored to both.

## 6. Windows-specific risks and required changes

1. **Line endings (highest risk).** On `windows-latest` and many Windows dev
   machines git checks out CRLF. Gateway-bound files must be LF: the systemd unit
   `iot-gateway-ids.service` (CRLF breaks `ExecStart` parsing), `ids_config.yaml`,
   `requirements-runtime.txt`, and all Python under `gateway/`. Add/extend
   `.gitattributes` (none exists now) with at least
   `gateway/** text eol=lf`, `*.service text eol=lf`, `*.sh text eol=lf`,
   `*.joblib binary`; then renormalize. Add a test that every file in
   `gateway/ids` shipped to the gateway contains no `\r\n` (except binaries).
2. **Text-mode temp file in `api/ids.py`.** `tempfile.NamedTemporaryFile("w",
   ...)` + `yaml.safe_dump` writes `\r\n` on Windows, so the uploaded
   `ids_config.yaml` would have CRLF. Open with `newline="\n"` (or write bytes).
   Same check for any other uploaded temp text.
3. **Packaging.** `iot-gateway-monitor.spec` already bundles the whole `gateway/`
   tree via `_tree(REPO / "gateway", "gateway")`, skipping `tests`, `build`,
   `dist`, venv, caches. That should include `ids_gateway/`, `models/*.joblib`,
   `configs/`, `requirements-runtime.txt`, and the `.service` file, and exclude
   `gateway/ids/tests` (fine). Verify rather than assume (section 7). Do not add
   LightGBM/scikit-learn/pandas to `apps/desktop/requirements.txt` or the spec's
   hidden imports. Check `gateway/ids/models/*.joblib` is not mangled by any
   text normalization.
4. **Remote paths must remain POSIX strings.** Provisioner/API build remote paths
   with f-strings (`/opt/...`), correct. Do not use `os.path`/`Path` for remote
   paths. Local asset lookup uses `Path` (`agent_src.parent / "ids"`), correct.
5. **Tar upload from Windows.** `SSHSession.upload_tree` tars the local tree and
   extracts remotely. Windows tar entries have synthetic modes, so do not rely on
   execute bits from the bundle: the IDS flow runs Python via
   `ids-venv/bin/python -m ...` and installs the unit explicitly, and this should
   stay that way. Confirm after extraction that ownership/permissions are sane
   (staged then moved with sudo).
6. **Credentials.** The sudo password comes from Windows Credential Manager via
   `keyring_store` and is injected by `wizard_server`; it travels only in the
   local request body to the control-service. Never log it (existing redaction
   patterns); keep `_should_inject_sudo` for `/ids/config`.
7. **Long operations.** First IDS provisioning installs apt + pip packages on the
   gateway (minutes on a Raspberry Pi). The `windows` branch's wall-clock
   `run()` helps; make sure the IDS steps pass generous `timeout=` values and
   surface timeouts as clear errors.
8. **Tests that assume POSIX.** The Python test files for the provisioner/API use
   fakes and should run on Windows; check any use of `/tmp`, file modes, or
   `shlex` splitting in assertions. Node UI test runs the same on Windows.
   Some existing telemetry tests are `skipUnless(os.name != "nt")`.
9. **Distribution.** CI signs the `.exe` when secrets are set; unsigned builds may
   trigger SmartScreen. Not IDS-related, but mention in test notes.
10. **UI embedding.** The packaged `.exe` embeds `apps/desktop/ui` at build time;
    UI changes appear only after rebuilding. Run the Node UI test against source.

Nothing else in the IDS design changes: still no Docker, no WSL, no ML packages
on the PC.

## 7. Step-by-step plan for Copilot

Work only in the `iot-gateway` repo, never in `IDS_Edge_Model` or
`iot-gateway-submit`.

1. **Prepare.** Make sure the Linux work is committed: `bdaf662` plus a new
   commit with `gateway/ids/tests/e2e/test_model_pipeline.py`,
   `gateway/ids/tests/fixtures/model_heldout_test.csv`, and the docs. Make
   sure `docs/` is not in `.gitignore` so the docs are tracked.
2. **Branch.** `git fetch`, then create a branch from `origin/windows`
   (for example `windows_ids`). Inspect `git status` first; preserve unrelated
   changes.
3. **Port.** `git cherry-pick bdaf662` (code applies cleanly; resolve the 3 doc
   conflicts), then cherry-pick the E2E/docs commit. Alternatively copy the files
   listed in section 4. Keep Windows-branch text in docs and add IDS content.
4. **Apply Windows fixes** from section 6 (items 1, 2 mandatory; verify 3, 5, 7).
5. **Docs.** Update `docs/architecture.md`, `docs/details.md`, `docs/UI.md`,
   `README.md`, and add `docs/ids*.md`. State clearly that the IDS runs on the
   Linux gateway, the Windows app only controls it, and list supported gateway
   architectures (Linux x86_64 and aarch64 only). Keep the unverified-hardware
   limitation.
6. **Test.** Run, from the repo root, the smallest relevant suites first:
   - `python -m pytest apps/control-service/tests/test_ids_api.py
     apps/control-service/provisioner/tests/test_provisioner.py
     apps/desktop/tests/test_ca_inject.py gateway/agent/tests
     gateway/ids/tests/test_structured_input.py`
     (use the repo's venv; add `gateway/ids` to `PYTHONPATH` for IDS tests).
   - `node --test apps/desktop/tests/security-ui.test.cjs`.
   - Offline model E2E only where LightGBM is installable:
     `PYTHONPATH=gateway/ids pytest -q gateway/ids/tests/e2e/test_model_pipeline.py`.
   - Fix failures caused by the port; known unrelated failures: Kafka layout
     fixture test, fake-device "stopped" message assertion.
7. **Package check.** Build with `bash apps/desktop/packaging/build_windows.sh`
   (on Windows or `windows-latest`). Verify the `.exe` bundle contains
   `gateway/ids/ids_gateway`, `models/ids_model.joblib`,
   `feature_scaler.joblib`, `model_metadata.json`, `configs/ids_config.yaml`,
   `requirements-runtime.txt`, `iot-gateway-ids.service`, and `ui/security.*`, and
   that the service file and requirements have LF endings and no LightGBM is
   bundled. (PyInstaller onefile: extract with `pyi-archive_viewer`, or run the
   provisioner against a fake SSH session using the frozen asset path.)
8. **Report.** List changed files, test results, and anything unverified.

## 8. Acceptance criteria

- `.exe` includes every IDS asset the provisioner needs and no ML runtime.
- Provisioning from the Windows app installs the IDS service and model on a
  Linux gateway, with LF-ending files; missing assets/unsupported arch/dependency
  failure/model failure are reported as failures.
- Security page on Windows: select gateway, see configured vs running state,
  enable/disable without restarting the MQTT/decrypt agent, alerts auto-refresh
  (15 s) with distinct error/empty/not-installed/disabled states, safe rendering.
- Uploaded config contains no CRLF; config writes are atomic.
- Existing monitoring, decrypt, and gateway behavior preserved; no blocking.
- Focused tests pass on Windows (or documented skips); docs updated.

## 9. Known limitations to carry forward (do not hide)

- Never validated on real Raspberry Pi/ARM/Linux gateway hardware, real systemd,
  aarch64 wheels, or live Loki delivery. Real-hardware performance is unmeasured.
- Offline E2E test not executed (LightGBM absent in the dev environment); the
  reported ~100% held-out precision/recall is metadata-reported, unverified.
- Training/runtime feature mismatch: training `payload_len` is the full raw JSON
  line vs. payload object at runtime; inter-arrival calculation differs; runtime
  scores about every second with a cleared buffer, which can be smaller than the
  3 s training windows. Live accuracy may differ from held-out numbers.
- Training artifacts inconsistencies (label threshold 0.34 vs. >=0.5 rule,
  trainer weights vs. metadata weights, metadata counts vs. confusion matrix) mean
  retraining reproducibility is not established.
- No source-IP, Node-RED denied-event, or HAProxy-based detections.
- No Windows `.exe` build or Windows run of these tests was performed for this
  document; section 5's dry run only proved the code merges cleanly.
