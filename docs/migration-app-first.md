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

1. Download the desktop app from GitHub Releases (`desktop-latest`) — no Docker on the PC.
2. Wizard → **Prepare monitoring** (native Loki/Prometheus) → SSH pin/key → **Install gateway agent** (native Mosquitto + monolithic agent; no Docker on the device).
3. Register devices via Actions (not Gitea workflows).
4. Collect sanitized support bundles from `support.write_support_bundle` when debugging.
5. Legacy compose gateways: set `IOTGW_GATEWAY_BACKEND=compose` only if you intentionally keep Docker on the device.

## Gitea

- **Default:** do not start `gitea` / `gitea-seed` / `gitearunner`.
- **Brownfield:** `docker compose --profile legacy-gitea up` under `monitoring/`.
- Workflows under `monitoring/scripts/gitea_actions/` are legacy; SSH playbooks in `apps/control-service/actions/` replace them.

## Decrypt path (K17)

The **decrypt → `sensor_data.log` path** stays mandatory. On the default (Docker-free) path it runs inside the monolithic `iot-gateway-agent`. Legacy compose installs may still use Node-RED.

## Artifact signing (K16 / PR 14)

CI may produce **unsigned** Windows/Ubuntu installers. Distribution signing is done in the **Admin → Code Signing** tab (OS keyring / secure prompt), not via long-lived CI org secrets alone. Gateway MQTT/TLS cert rotation is a separate concern (`apps/control-service/certs/`).

## Rollback

- Gateway file mutations keep `*.bak.<epoch>` backups; provisioner can restore `/opt/iot-gateway.bak-<ts>`.
- Monitoring lab compose remains available under “Advanced / legacy” in the README if you need to fall back while adopting the app.
