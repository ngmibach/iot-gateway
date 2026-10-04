# IoT Gateway Monitor

Cross-platform control plane for the IoT gateway: **discover the device on your LAN → SSH install the gateway stack → open Monitoring + Actions**. You do not need to run `docker compose` or hand-edit IPs for the default path.

| Piece | Role |
|-------|------|
| **Desktop app** (Phase-0: Streamlit + control service; Phase-1: Tauri) | Setup Wizard, Monitoring, Actions, Admin |
| **Control service** (`apps/control-service/`) | SSH provision/register playbooks, local SQLite registry, support bundle |
| **Gateway** (on Ubuntu / Raspberry Pi) | Mosquitto, HAProxy, **Node-RED (mandatory)**, IDS, exporters, optional agent |
| **Observability** | App-managed Loki + Prometheus (Grafana optional) |

Design reference: `DESIGN-packaged-app.md` (when present in the tree).

---

## Recommended path (app-first)

### 1. Install / start the control plane on your operator PC

```shell
cd apps/control-service
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt

# Local API (binds 127.0.0.1:9137 only)
export IOTGW_CA_PASSPHRASE='…'          # gateway CA unlock for CSR sign
export IOTGW_SSH_KEY=~/.ssh/id_ed25519  # or IOTGW_SSH_PASSWORD
python -m api
```

Phase-0 UI: run Streamlit on the **host** (not inside the monitoring compose container) so it can reach the local API:

```shell
export CONTROL_SERVICE_URL=http://127.0.0.1:9137
export LOKI_URL=http://127.0.0.1:3100
export PROMETHEUS_URL=http://127.0.0.1:9090
# USE_LEGACY_GITEA is off by default — do not set it for the app-first path
streamlit run monitoring/build/streamlit/app.py
```

### 2. Discover → SSH → install gateway

1. Enter the gateway LAN IP (mDNS via `iot-gateway-agent` is optional until after first install).
2. Authenticate with the device SSH password or key.
3. Provision uploads the gateway bundle, runs `docker compose up`, probes exporters/Loki, then installs the agent **last**.

CLI dogfood (when the provisioner module is on your branch/PYTHONPATH):

```shell
PYTHONPATH=apps/control-service python -m provisioner provision \
  --host "$GATEWAY_IP" --user ubuntu \
  --gateway-ip "$GATEWAY_IP" --monitoring-ip "$MONITORING_IP"
```

### 3. Register devices & open the dashboard

- **Actions → Register Device**: ACL + hashed Mosquitto password + HAProxy allow-list + mTLS client cert (one-time download token).
- **Monitoring**: sensors / gateway / Raspberry Pi views against Loki + Prometheus.

### 4. Support bundle (sanitized)

```shell
PYTHONPATH=apps/control-service python -c "
from pathlib import Path
from api.settings import Settings
from registry.registry import Registry
from support import write_support_bundle, default_bundle_path
s = Settings.from_env()
r = Registry(str(s.registry_path))
path = write_support_bundle(default_bundle_path(s.data_dir), settings=s, registry=r)
print(path)
"
```

Export includes redacted settings, registry snapshot, audit log, and recent control logs. **No** passwords, API tokens, PEMs, or keyring/signing material.

---

## Node-RED is mandatory (K17)

The gateway stack **must** keep Node-RED. It owns the decrypt → `sensor_data.log` path consumed by the IDS and dashboards. Removing or replacing Node-RED is out of scope for v1. Provision and compose checks treat a missing `nodered` service as a failure.

---

## Artifact signing — Admin Code Signing (not CI-only secrets)

Release binaries (Windows `.msi`/`.exe`, Ubuntu AppImage/`.deb`) are **built unsigned in CI**. Shipping signatures are applied from the **Admin → Code Signing** tab (PR 14): the admin loads signing material via OS keyring / secure prompt and signs locally. Do not rely on long-lived org CI secrets as the only signing path. See migration notes in `docs/migration-app-first.md`.

---

## Gitea control plane — deprecated / optional

Day-2 mutations (register, ACL, allow-list, clear logs) go through the **control service over SSH**. Gitea + runner + seed remain in `monitoring/docker-compose.yaml` only under the Compose profile `legacy-gitea` for brownfield labs. Leave `USE_LEGACY_GITEA` unset (legacy only enables for `1`/`true`/`yes`).

```shell
# Only if you intentionally need the old Actions runner:
docker compose -f monitoring/docker-compose.yaml --profile legacy-gitea up -d
```

---

## Advanced / legacy: three-folder Docker Compose

Power users can still run the classic stacks by hand. Prefer the app-first path above for new installs.

### Prerequisites

- Docker + Docker Compose, `openssl`
- Network reachability to the gateway host

### Certificates

```shell
# Set SERVER_CN to the gateway IP inside cert-generation.sh, then:
bash cert-generation.sh
```

### Start order

```shell
cd gateway && docker compose build && docker compose up -d
cd ../monitoring && docker compose build && docker compose up -d   # Gitea profile optional
# Optional lab traffic:
cd ../fake_sensor && docker compose build && docker compose up -d
```

Fake sensors should only run for short windows. Allow their Docker bridge IPs in `gateway/haproxy/allowed-ips.txt`, then reload HAProxy.

### Legacy URLs (compose lab)

| Service | URL | Notes |
|---------|-----|-------|
| Streamlit | http://localhost:8000 | Prefer host Streamlit + `CONTROL_SERVICE_URL` for Register Device |
| Grafana | http://localhost:3210 | `admin` / `admin` |
| Prometheus | http://localhost:9090 | |
| Loki | http://localhost:3100 | |
| Gitea | http://localhost:5000 | **Deprecated** control plane; profile `legacy-gitea` |

Template-rendered endpoints live under `deploy/templates/` (`MONITORING_IP` / `GATEWAY_IP`). Avoid hard-coding `172.17.0.1`.

---

## Tests (CI-friendly)

```shell
cd apps/control-service
PYTHONPATH=. python -m unittest discover -s tests -v
# Includes support-bundle redaction + mocked Linux register/provision E2E
PYTHONPATH=. python -m unittest tests.e2e.test_linux_register_provision -v
```

No Raspberry Pi is required for CI; live checklist text is in `tests/e2e/linux_happy_path.py`.

---

## Repository layout

```
apps/control-service/   # FastAPI, SSH actions, registry, telemetry, support bundle
deploy/templates/       # IP-templated Promtail/Prometheus/Grafana snippets
gateway/                # Device compose stack (Node-RED mandatory)
monitoring/             # Lab compose (Loki/Prom/Grafana/Streamlit; Gitea optional)
fake_sensor/            # Lab only
docs/migration-app-first.md
```
