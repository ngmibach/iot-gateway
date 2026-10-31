# Architecture

Overview of IoT Gateway Monitor and the gateway agent. Diagrams only â€” paths, APIs, flags, and formulas live in [`details.md`](details.md). Operator click-paths live in [`UI.md`](UI.md).

## 1. System top level

The system has two applications: the **monitoring app** on the operator PC, and the **gateway agent** on each edge device (for example a Raspberry Pi). Control and provision use SSH. Sensor data uses MQTTS. Metrics and logs flow back to the PC over HTTP.

```mermaid
flowchart LR
  subgraph PC["Operator PC â€” Monitoring app"]
    UI["Desktop UI\nWizard Â· Gateways Â· Monitoring Â· Settings"]
    CS["Control service"]
    PROM["Prometheus"]
    LOKI["Loki"]
    GRAF["Grafana"]
  end

  subgraph GW["Gateway device â€” Agent"]
    AGENT["iot-gateway-agent"]
    MQTT["Mosquitto MQTTS :8883"]
    KAFKA["Kafka KRaft"]
  end

  SENSORS["Sensors / fake sensors"]

  UI --> CS
  CS -->|"SSH provision & day-2"| AGENT
  SENSORS -->|"MQTTS mTLS + password"| MQTT
  MQTT --> AGENT
  AGENT --> KAFKA
  AGENT -->|"ship logs"| LOKI
  PROM -->|"scrape :9139/metrics"| AGENT
  CS --> PROM
  CS --> LOKI
  GRAF --> PROM
  GRAF --> LOKI
  GRAF -->|"Kafka datasource"| KAFKA
```

## 2. Monitoring application

Packaged desktop app (`IoTGatewayMonitor.exe` / AppImage). No Docker and no WSL required on Windows. Loki, Prometheus, and Grafana run as native processes under the app data directory.

```mermaid
flowchart TB
  subgraph Desktop["IoT Gateway Monitor"]
    WIZ["Wizard / UI :9138"]
    CTRL["Control service :9137"]
    REG["registry.sqlite\ngateways + devices"]
    KEY["OS keyring\nCA Â· sudo Â· admin PIN"]
    RENEW["FakeCertRenewer\nfakes only"]
  end

  LOKI["Loki :3100"]
  PROM["Prometheus :9090"]
  GRAF["Grafana HTTPS :9140"]

  WIZ --> CTRL
  CTRL --> REG
  CTRL --> KEY
  CTRL --> RENEW
  CTRL --> LOKI
  CTRL --> PROM
  WIZ -->|"open system browser"| GRAF
  GRAF --> LOKI
  GRAF --> PROM
```

| Piece | Role |
|-------|------|
| Wizard / UI | First-run install, Gateways, Monitoring, Control Plane, Settings |
| Control service | Registry, SSH playbooks, query APIs, secret injection |
| Loki / Prometheus / Grafana | Local observability stack (downloaded once in-UI) |
| Keyring | CA passphrase and gateway sudo after Install |

## 3. Gateway application

One systemd agent under `/opt/iot-gateway-agent`, with system Mosquitto and Apache Kafka KRaft beside it. Optional fake sensors share a private bridge on the gateway.

```mermaid
flowchart TB
  subgraph Gateway["Gateway device"]
    MOSQ["Mosquitto\nMQTTS :8883 mTLS"]
    DEC["Decrypt worker"]
    LOG["sensor_data.log"]
    KAFKA["iotgw-kafka\nINTERNAL :9092 / EXTERNAL :9094"]
    SHIP["Loki shipper"]
    MET["/metrics Â· /v1/health\n:9139"]
    FAKE["iotgw-fake bridge\n10.255.0.0/24\niotgw-fake@ units"]
  end

  SENSORS["Real sensors"] --> MOSQ
  FAKE --> MOSQ
  MOSQ --> DEC
  DEC --> LOG
  DEC --> KAFKA
  LOG --> SHIP
  SHIP -->|"MONITORING_IP:3100"| LOKI["Operator Loki"]
  MET -->|"Prometheus scrape"| PROM["Operator Prometheus"]
```

Canonical application order in Metric UI: **Agent â†’ MQTT â†’ Decrypt â†’ Shipper â†’ Kafka**.

## 4. Verification and storage path

A sensor may publish only after registration (MQTT user + ACL + client cert + Kafka topic). The gateway always decrypts so it can validate schema, append the local log, and produce Kafka.

```mermaid
sequenceDiagram
  participant S as Sensor
  participant M as Mosquitto :8883
  participant D as Decrypt worker
  participant K as Kafka topic
  participant L as sensor_data.log
  participant Ship as Shipper

  S->>M: MQTTS connect (password + client cert)
  M->>M: ACL / password / mTLS check
  S->>M: Publish envelope (or legacy) topics
  M->>D: Deliver to decrypt subscription
  D->>D: Pair / unwrap / AES-GCM / schema
  D->>L: Append plaintext line
  D->>K: Produce sensor.device_id
  L->>Ship: Tail lines
  Ship->>Ship: Push to operator Loki
```

One Kafka topic per registered sensor (`sensor.<device_id>`), size-capped by retention so capacity stays bounded. See [`details.md`](details.md#sensor-capacity-kafka).

## 5. Encryption and decryption overview

Two independent layers: **transport** (MQTTS mTLS) and **application** (envelope v1). Transport answers who may connect. Envelope answers confidentiality of JSON after TLS termination.

```mermaid
flowchart LR
  subgraph Transport["Transport"]
    TLS["MQTTS :8883\npassword + client cert"]
  end

  subgraph App["Application envelope v1"]
    KEY["PUB sensors/id/env/key"]
    DATA["PUB sensors/id/env/data"]
    PAIR["Pair by msg_id"]
    UNWRAP["Unwrap CEK\nPSK or DMEC"]
    GCM["AES-128-GCM open"]
    SCHEMA["Schema validate"]
  end

  TLS --> KEY
  TLS --> DATA
  KEY --> PAIR
  DATA --> PAIR
  PAIR --> UNWRAP
  UNWRAP --> GCM
  GCM --> SCHEMA
  SCHEMA --> OUT["sensor_data.log Â· Kafka Â· Loki"]
```

Profiles: `v1-psk` (registration wrap secret) and `v1-ecdhe` (ephemeral ECDH + daily DMEC). Legacy Fernet remains accepted until `IOTGW_ENVELOPE_REQUIRE=1`. Full reference: [`details.md` â€” Encryption](details.md#encryption-envelope-v1).

## 6. Monitoring operations

### 6.1 Spawn and register a gateway

```mermaid
flowchart LR
  A["Find gateway\nSSH scan :22"] --> B["Select host"]
  B --> C["Install gateway"]
  C --> D["Pin host key Â· SSH key\nfirewall if needed"]
  D --> E["Provision agent\nMosquitto Â· Kafka Â· CA"]
  E --> F["Upsert registry.sqlite"]
  F --> G["Prometheus scrape target\n:9139"]
```

Install bootstraps the gateway CA, server cert, decrypt client cert, Kafka catalog, and stores CA/sudo secrets in the operator keyring for day-2 actions.

### 6.2 Monitor metrics and activities

```mermaid
flowchart TB
  AGENT["Gateway agent :9139"]
  PROM["Prometheus"]
  LOKI["Loki"]
  API["Control service\nsummaries APIs"]
  METRIC["UI Â· Gateway Metric"]
  ACT["UI Â· Gateway Activities"]

  AGENT -->|"/metrics"| PROM
  AGENT -->|"shipper"| LOKI
  PROM --> API
  LOKI --> API
  API --> METRIC
  API --> ACT
```

- **Metric** â€” host health (CPU, RAM, FS, net, temp) and application up/activity for Agent, MQTT, Decrypt, Shipper, Kafka.
- **Activities** â€” gateway-wide and per-sensor message counters, Kafka topic metadata, transmission delay, Fake/Real type.

### 6.3 Spawn and register fake sensors

```mermaid
flowchart LR
  C["Create fake sensor"] --> N["Allocate IP on\niotgw-fake bridge"]
  N --> R["Register like real\nMQTT Â· cert Â· Kafka"]
  R --> U["iotgw-fake@ unit\ncreated stopped"]
  U --> S["Simulate Â· Start"]
  S --> P["Publish MQTTS\nenvelope traffic"]
  RENEW["FakeCertRenewer"] -.->|"auto-feed mTLS"| U
```

Fakes count toward the same Kafka capacity as real sensors. Gateway uninstall tears down all fake units, netns, and the bridge.

## Related docs

| Doc | Contents |
|-----|----------|
| [`details.md`](details.md) | Ports, paths, APIs, capacity formula, encryption reference |
| [`UI.md`](UI.md) | How to use each tab and feature |
| [`samples/fake-sensor-payload.json`](samples/fake-sensor-payload.json) | Sample manufacturing payload for Simulate |
)
