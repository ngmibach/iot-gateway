# IDS Behavioral Rules

Post-gateway detections for the IoT gateway IDS (`iot-ids`). Rules inspect accepted `sensor_data` plus correlated signals from Node-RED denied events, Mosquitto connect/publish churn, HAProxy TLS failures, and gateway state prom files.

**Implementation status (2026-06-21):** All rules that do **not** require ML retraining are **implemented** in `ids_gateway/rules.py`. ML-only features are documented under [ML retrain guide](#ml-retrain-guide).

---

## Log sources wired into IDS

| Source | Path in container | Capture class |
|--------|-------------------|---------------|
| Node-RED sensor log | `/app/nodered_logs/sensor_data.log` | `SensorLogCapture` |
| Mosquitto broker log | `/mosquitto/log/mosquitto.log` | `MosquittoLogCapture` |
| HAProxy log | `/haproxy-logs/haproxy.log` | `HaproxyLogCapture` |
| Active sensors prom | `/textfile/active_sensors.prom` | `GatewayStateReader` |
| Allowed IPs / ACL prom | `/textfile/allowed_ips.prom` | `GatewayStateReader` |
| Gateway state log | `/var/log/iot-gateway/gateway-state.log` | `GatewayStateReader` |

Restart after code changes:

```bash
docker compose up -d --build ids
```

---

## Implemented behavioral rules

Configured in `configs/ids_config.yaml`. All alerts use a **60 s per-device per-rule cooldown** (`alert_cooldown_seconds`) to avoid duplicate rows.

### Identity / gateway state

| Rule | Severity | Threshold (default) |
|------|----------|---------------------|
| `unknown_acl_user` | critical | Device ∉ Mosquitto ACL users |
| `source_ip_not_allowed` | critical | IP ∉ `allowed_ips.prom` |
| `source_ip_baseline` | critical | IP ≠ known device IP from `active_sensors.prom` |
| `inactive_sensor_traffic` | warning | Device ∉ `active_sensors.prom` (skipped when prom empty) |
| `cross_ip_identity` | critical | Accepted traffic from >1 IP for same device |

### Payload / Node-RED denied events

| Rule | Severity | Threshold (default) |
|------|----------|---------------------|
| `deny_accept_ratio` | critical | denied/(denied+accepted) > **10%** in 60 s |
| `undersize_payload_campaign` | critical | ≥ **3** denied payloads < **2500** B in 60 s |
| `denied_probe_burst` | warning | ≥ **5** consecutive denied without accepted |
| `payload_reject_storm` | critical | ≥ **5** denied in 60 s |
| `accepted_size_drift` | warning | Accepted size ∉ **{2769, 2793}** |

### Timing / rate (accepted sensor_data)

| Rule | Severity | Threshold (default) |
|------|----------|---------------------|
| `future_timestamp` | warning | delay < 0 (device clock ahead of gateway) |
| `clock_skew_anomaly` | warning | delay > **2.5 s** |
| `high_message_rate` | warning | > **1.5** msg/s |
| `accelerated_publishing` | warning | min IAT < **900 ms** |
| `rapid_fire` | warning | mean IAT < **80 ms**, ≥ 3 msgs |

### MQTT / TLS (Mosquitto + HAProxy)

| Rule | Severity | Threshold (default) |
|------|----------|---------------------|
| `mqtt_connect_churn` | warning | connect rate > **1.5/s** OR ≥ **10** connects in 60 s |
| `connect_publish_ratio` | warning | connects/publishes > **1.15** in 60 s |
| `ephemeral_client_churn` | warning | unique `auto-*` client IDs > **1.25×** publish count |
| `mqtt_multi_ip_connect` | critical | Same MQTT user from >1 IP |
| `ssl_handshake_storm` | warning | ≥ **10** HAProxy SSL failures per IP in 60 s |

### Composite

| Rule | Severity | Condition |
|------|----------|-----------|
| `attack_triad` | critical | `deny_accept_ratio` + `connect_publish_ratio` + `ssl_handshake_storm` thresholds all met |

### ML model (unchanged — no retrain)

LightGBM on 12 features per 3 s window. Confirmed `message_pattern_anomaly` alert after sustained high-score windows.

---

## Production log baseline

| Metric | sensor1–3 (benign) | sensor4 (attack) |
|--------|-------------------|------------------|
| Denied / total ratio | 0% | **51.9%** |
| Accepted payload size | 2769, 2793 | 2769 (5), 2793 (248) |
| Denied payload size | — | 2215–2222 |
| MQTT connect / publish | **1.00** | **1.32** |
| HAProxy SSL failures | — | **246** (same IP) |

Rules most effective against the observed sensor4 campaign: `deny_accept_ratio`, `connect_publish_ratio`, `payload_reject_storm`, `ssl_handshake_storm`, `attack_triad`.

---

## ML retrain guide

The current model (`models/ids_model.joblib`) was trained on **12 features** from accepted `sensor_data` windows only. Training metadata is in `models/model_metadata.json` (dataset: `ids_features_gateway_message_v2.csv`, threshold: **0.05**, group split by `session_id`).

### When to retrain

Retrain when you want the ML layer to detect patterns that **rules cannot express cleanly**, especially:

- Subtle payload/timing anomalies with low denied ratio
- Attacks where accepted messages look normal but cross-signal features differ
- Reducing false positives on `clock_skew_anomaly` by learning delay distribution

### Proposed new ML features

Add these to the feature extractor and training CSV before retraining:

| Feature | Source | Rationale |
|---------|--------|-----------|
| `deny_ratio` | Node-RED denied + accepted in window | 0% benign vs 52% attack |
| `deny_rate` | Denied events / window seconds | Probe speed |
| `connect_publish_ratio` | Mosquitto log | sensor4 churn signature |
| `connect_count` | Mosquitto log | Raw reconnect volume |
| `delay_std` | sensor_data `delay` field | Jitter profile |
| `payload_size_delta` | `payload_size_bytes` vs mode 2793 | Undersize attack fingerprint |
| `undersize_event_ratio` | Fraction of events < 2500 B | Denied campaign density |
| `ssl_fail_count` | HAProxy log in same window | TLS probe correlation |
| `iat_coefficient_variation` | `std_iat / mean_iat` | Benign CV ≈ 0.08 |

**Priority for first retrain:** `deny_ratio` + `connect_publish_ratio` + `payload_size_delta`.

### Step 1 — Extend feature extraction

Edit `ids_gateway/features.py`:

1. Add new names to `FEATURE_NAMES`.
2. Extend `build_feature_vector()` to accept optional correlated context (denied counts, mqtt stats, ssl stats) **or** pre-join these into `PacketRecord.extra` before calling `build_feature_vector`.
3. Keep backward compatibility by defaulting new features to `0.0` when context is missing.

Example signature change:

```python
def build_feature_vector(
    records: List[PacketRecord],
    *,
    denied_count: int = 0,
    accepted_count: int = 0,
    mqtt_stats: MqttConnectStats | None = None,
    ssl_failures: int = 0,
) -> Dict[str, float]:
    ...
```

### Step 2 — Build training dataset

The original pipeline produced `data/processed/ids_features_gateway_message_v2.csv` with columns matching `FEATURE_NAMES` plus `label` and `session_id`.

To rebuild:

1. **Collect labeled sessions** — benign sensor logs (`sensor1_benign_*`) and attack sessions (`light_attack_*`, `mid_attack_*`, `heavy_attack_*`) as JSONL or from `sensor_data.log` exports.
2. **Window the data** — same 3 s buckets as runtime (`packet_window_seconds`).
3. **Compute all features** — use the updated `build_feature_vector()` plus session metadata.
4. **Label rows** — `label=1` for attack windows, `label=0` for benign.
5. **Group by `session_id`** — keep group-based train/val/test split (no leakage across sessions).

Minimum CSV columns:

```
session_id,device_id,source_ip,msg_count,...,deny_ratio,connect_publish_ratio,label
```

### Step 3 — Train LightGBM

Training code is not in this repo; use your ML pipeline (or recreate with scikit-learn/lightgbm):

```python
import joblib
import lightgbm as lgb
import pandas as pd

FEATURES = [...]  # all old + new feature names
df = pd.read_csv("data/processed/ids_features_gateway_message_v3.csv")

groups = df["session_id"]
# group-aware split: train/val/test by session_id

train_data = lgb.Dataset(X_train, label=y_train)
model = lgb.train(
    {"objective": "binary", "metric": "auc", "num_leaves": 31},
    train_data,
    num_boost_round=200,
)
```

Tune threshold on validation set targeting **FPR ≤ 2%** (same as current `model_metadata.json`).

### Step 4 — Export model artifacts

Replace files under `ids/models/`:

| File | Purpose |
|------|---------|
| `ids_model.joblib` | Trained LightGBM booster |
| `feature_scaler.joblib` | Optional scaler (currently disabled) |
| `model_metadata.json` | Feature list, threshold, split stats, importances |

Update `model_metadata.json`:

```json
{
  "feature_columns": ["msg_count", "...", "deny_ratio", "connect_publish_ratio"],
  "selected_threshold": 0.05
}
```

### Step 5 — Update runtime config

Edit `configs/ids_config.yaml`:

```yaml
model:
  expected_features:
    - msg_count
    # ... all new feature names in the same order as training
    - deny_ratio
    - connect_publish_ratio
    - payload_size_delta
```

### Step 6 — Wire context into the detector

Edit `ids_gateway/detector.py` and `ids_gateway/main.py` to pass denied/mqtt/ssl context into `build_feature_vector()` so runtime features match training.

### Step 7 — Rebuild and validate

```bash
docker compose build ids
docker compose up -d ids
docker logs -f iot-ids
```

Replay labeled logs and confirm:

- Attack sessions score above threshold
- Benign sensor1–3 sessions stay below threshold
- New features are non-zero during sensor4-style campaigns

---

## Post-retrain ML detections

After retrain, the ML layer can surface alerts that rules may miss:

| Detection | How it appears | When it fires |
|-----------|----------------|---------------|
| `message_pattern_anomaly` | `alert_type: ml_anomaly` | Sustained high ML score across aggregation windows |
| Low-rate undersize campaign | ML via `undersize_event_ratio` + `payload_size_delta` | Attacker stays under rule thresholds but payload profile drifts |
| Subtle reconnect pattern | ML via `connect_count` + `connect_publish_ratio` | Churn below rule ratio but still anomalous in combination |
| Delay jitter change | ML via `delay_std` + `iat_coefficient_variation` | Clock skew under 2.5 s but timing pattern abnormal |

Keep behavioral rules enabled after retrain — rules give **explainable, immediate** alerts; ML catches **composite/statistical** anomalies.

---

## Explicitly out of scope (handled upstream)

- IP whitelist → HAProxy
- ACL topic deny → Mosquitto
- Payload size block → Node-RED (`denied_payload_size`)
- Topic/device mismatch → Mosquitto ACL + Node-RED

---

## Files reference

| File | Purpose |
|------|---------|
| `ids_gateway/rules.py` | All behavioral rule checks |
| `ids_gateway/log_capture.py` | Sensor, Mosquitto, HAProxy log tails |
| `ids_gateway/features.py` | ML feature vector (extend for retrain) |
| `ids_gateway/alerts.py` | Suspicion catalog for dashboard |
| `ids_gateway/main.py` | Main loop, context wiring |
| `configs/ids_config.yaml` | Thresholds and log paths |
| `docker-compose.yaml` | Volume mounts for logs + prom files |