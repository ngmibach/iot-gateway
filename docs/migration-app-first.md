# Migration: compose lab → app-first control plane

This project is moving from a three-folder Docker Compose lab (gateway + monitoring + fake_sensor) with **Gitea Actions** as the control plane to a packaged operator app: discover → SSH provision → Monitoring/Actions, with a local FastAPI control service.

## Phases

| Phase | What changes |
|-------|----------------|
| M1 | `apps/` added; gateway templates pin cAdvisor `:8080`; monitoring compose remains for power users |
| M2 | SSH action modules + brownfield registry import (ACL / allow-list) |
| M3 | Desktop app GA; **README is app-first** (this release) |
| M4 | **Gitea deprecated** from the default path (Compose profile `legacy-gitea` only) |
| M5 | `fake_sensor` = Lab panel only |

## Operator checklist

1. Install/run `apps/control-service` on the operator PC (`python -m api` on `127.0.0.1:9137`).
2. Point Streamlit (host process) at `CONTROL_SERVICE_URL`; leave `USE_LEGACY_GITEA` unset.
3. Provision the gateway over SSH (bundle upload + compose + probes; agent last).
4. Register devices via Actions (not Gitea workflows).
5. Collect sanitized support bundles from `support.write_support_bundle` when debugging.

## Gitea

- **Default:** do not start `gitea` / `gitea-seed` / `gitearunner`.
- **Brownfield:** `docker compose --profile legacy-gitea up` under `monitoring/`.
- Workflows under `monitoring/scripts/gitea_actions/` are legacy; SSH playbooks in `apps/control-service/actions/` replace them.

## Node-RED (K17)

Node-RED stays **mandatory** on the gateway in v1 (decrypt → `sensor_data.log` for IDS/dashboards). Do not remove it from `gateway/docker-compose.yaml` during migration.

## Artifact signing (K16 / PR 14)

CI may produce **unsigned** Windows/Ubuntu installers. Distribution signing is done in the **Admin → Code Signing** tab (OS keyring / secure prompt), not via long-lived CI org secrets alone. Gateway MQTT/TLS cert rotation is a separate concern (`apps/control-service/certs/`).

## Rollback

- Gateway file mutations keep `*.bak.<epoch>` backups; provisioner can restore `/opt/iot-gateway.bak-<ts>`.
- Monitoring lab compose remains available under “Advanced / legacy” in the README if you need to fall back while adopting the app.
