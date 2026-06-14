# IDS Model README

## 1. Scope
This README describes how to:
- start the IDS gateway runtime,
- run benchmark and live tests,
- collect and read outputs,
- understand the purpose of the test scripts.

All commands below are tested from this repository structure.

## 2. Key Paths
- IDS root: `gateway/ids`
- Gateway compose: `gateway/docker-compose.yaml`
- Fake sensor compose: `fake_sensor/docker-compose.yaml`
- Main runtime config: `gateway/ids/configs/ids_config.yaml`

## 3. Prerequisites
- Docker and Docker Compose installed.
- Python venv for host-side train/eval scripts:

```bash
cd /home/thuc/workspace/iot-gateway/gateway/ids
python3 -m venv .venv_ids_eval
. .venv_ids_eval/bin/activate
pip install -r requirements-runtime.txt
```

If your environment already has `.venv_ids_eval`, just activate it.

## 4. Runtime Flow

### Step A - Build fake sensors
Required only after changing any sensor scripts under `fake_sensor/build/sensor*/`.

```bash
cd /home/thuc/workspace/iot-gateway/fake_sensor
docker compose build sensor1 sensor2 sensor3 sensor4
```

### Step B - Start IDS gateway runtime
```bash
cd /home/thuc/workspace/iot-gateway/gateway
docker compose up -d --force-recreate ids-gateway
```

Tag explanation:
- `up -d`: start container in detached mode.
- `--force-recreate`: recreate the container so the next log stream starts from a clean runtime instance.
- `ids-gateway`: only restart the IDS service, not the whole stack.

Check status:

```bash
docker ps | grep iot-ids-gateway
```

Tag explanation:
- `docker ps`: list running containers.
- `grep iot-ids-gateway`: filter the IDS container from the full list.

Follow runtime logs:

```bash
docker logs -f iot-ids-gateway
```

Tag explanation:
- `logs -f`: follow logs in real time.
- `iot-ids-gateway`: IDS gateway container name.

## 5. Run Tests

### 5.1 Single multi-sensor benchmark (IP-level report)
```bash
cd /home/thuc/workspace/iot-gateway
ATTACK_DEVICES=sensor1,sensor3 \
ATTACK_LEVEL=heavy \
BROKER_HOST=172.31.217.41 \
BROKER_PORT=1883 \
USE_TLS=0 \
BENIGN_DURATION=8 \
ATTACK_DURATION=14 \
OUT_LOG=gateway/ids/logs/multi_sensor_ids_full.log \
OUT_JSON=gateway/ids/logs/multi_sensor_ip_eval.json \
bash gateway/ids/scripts/run_multi_sensor_ip_benchmark.sh
```

Tag explanation:
- `ATTACK_DEVICES=sensor1,sensor3`: choose which fake sensors behave as attackers.
- `ATTACK_LEVEL=heavy`: attack intensity profile. Common values are `light`, `heavy`, and `mixed`.
- `BROKER_HOST=172.31.217.41`: MQTT broker host reachable from fake sensor containers.
- `BROKER_PORT=1883`: MQTT broker port.
- `USE_TLS=0`: disable TLS for this test. Use `1` when testing TLS mode.
- `BENIGN_DURATION=8`: benign phase duration in seconds before attack starts.
- `ATTACK_DURATION=14`: attack phase duration in seconds.
- `OUT_LOG=...`: file path to save raw IDS runtime logs for this run.
- `OUT_JSON=...`: file path to save the final IP-level evaluation result.
- `bash gateway/ids/scripts/run_multi_sensor_ip_benchmark.sh`: run the full multi-sensor benchmark wrapper.

### 5.2 Matrix benchmark with confidence interval
```bash
cd /home/thuc/workspace/iot-gateway
. gateway/ids/.venv_ids_eval/bin/activate
python gateway/ids/scripts/run_ip_benchmark_matrix.py \
  --repeats 3 \
  --broker-host 172.31.217.41 \
  --broker-port 1883 \
  --use-tls 0 \
  --benign-duration 8 \
  --attack-duration 14 \
  --output-json gateway/ids/logs/ip_benchmark_matrix_summary.json \
  --output-md gateway/ids/logs/model_performance_report.md
```

Tag explanation:
- `--repeats 3`: run each benchmark profile three times.
- `--broker-host 172.31.217.41`: broker host reachable from the fake sensors.
- `--broker-port 1883`: broker port.
- `--use-tls 0`: disable TLS during benchmark.
- `--benign-duration 8`: benign stage length per run.
- `--attack-duration 14`: attack stage length per run.
- `--output-json ...`: write machine-readable aggregated benchmark summary.
- `--output-md ...`: write human-readable markdown performance report.

### 5.3 Live test and monitoring
Terminal 1 - message stream from sensors:
```bash
cd /home/thuc/workspace/iot-gateway
docker logs -f iot-ids-gateway 2>&1 | stdbuf -oL grep -aE '\[IDS\] device='
```

Tag explanation:
- `2>&1`: merge stderr into stdout so the filter sees all log lines.
- `stdbuf -oL`: force line-buffered output for smoother real-time streaming.
- `grep -aE`: treat stream as text and filter only lines matching the regex.
- `\[IDS\] device=`: show per-message IDS decisions from different sensors.

Terminal 2 - block events only:
```bash
cd /home/thuc/workspace/iot-gateway
docker logs -f iot-ids-gateway 2>&1 | stdbuf -oL awk '/blocked \(ip_aggregated_ml\)/ {print $NF}'
```

Tag explanation:
- `awk '/blocked \(ip_aggregated_ml\)/ ...'`: keep only IP-level block events.
- `print $NF`: print the last field, which is the blocked IP address.

Terminal 3 - block events with decision context:
```bash
cd /home/thuc/workspace/iot-gateway
docker logs -f iot-ids-gateway 2>&1 | stdbuf -oL awk '
/\[IDS\] device=/ {
  if (match($0,/src=([^ ]+)/,a)) ip=a[1]
  if (match($0,/score=([0-9.]+)/,b)) dscore[ip]=b[1]
  if (match($0,/pkt_count=([0-9.]+)/,c)) pkt[ip]=c[1]
  if (match($0,/iat_ms=([0-9.]+)/,d)) iat[ip]=d[1]
  if (match($0,/topic=([^ ]+)/,e)) topic[ip]=e[1]
}
/\[IDS\] ip_eval/ {
  if (match($0,/src=([^ ]+)/,a)) ip=a[1]
  if (match($0,/windows=([0-9]+)/,b)) win[ip]=b[1]
  if (match($0,/attack_windows=([0-9]+)/,c)) aw[ip]=c[1]
  if (match($0,/vote_ratio=([0-9.]+)/,d)) vr[ip]=d[1]
  if (match($0,/avg_score=([0-9.]+)/,e)) avg[ip]=e[1]
  if (match($0,/ip_attack=([A-Za-z]+)/,f)) ipa[ip]=f[1]
}
/blocked \(ip_aggregated_ml\)/ {
  ip=$NF
  print "[BLOCK] ip=" ip \
        " last_device_score=" dscore[ip] \
        " avg_score=" avg[ip] \
        " vote_ratio=" vr[ip] \
        " attack_windows=" aw[ip] "/" win[ip] \
        " ip_attack=" ipa[ip] \
        " basis(topic=" topic[ip] ",pkt_count=" pkt[ip] ",iat_ms=" iat[ip] ")"
  fflush()
}'
```

Tag explanation:
- First `awk` block after `/\[IDS\] device=/`: cache the latest per-IP message score and context.
- Second `awk` block after `/\[IDS\] ip_eval/`: cache the latest IP aggregation metrics.
- Third `awk` block after `/blocked \(ip_aggregated_ml\)/`: print the blocked IP together with the latest score, vote ratio, attack window count, topic, packet count, and inter-arrival time.

## 6. Script Functions

- `gateway/ids/scripts/run_multi_sensor_ip_benchmark.sh`
  - Launches 4 fake sensors.
  - Chooses attacker devices via `ATTACK_DEVICES`.
  - Collects IDS logs for the run.
  - Produces an IP-level JSON report.

- `gateway/ids/scripts/eval_multi_sensor_ip_detection.py`
  - Parses IDS logs.
  - Converts per-message decisions into IP-level TP/TN/FP/FN metrics.
  - Treats an IP as attack if it is blocked or any IP-level attack vote appears.

- `gateway/ids/scripts/run_ip_benchmark_matrix.py`
  - Runs multiple benchmark profiles repeatedly.
  - Aggregates metrics across runs.
  - Computes Wilson 95% confidence interval for recall.
  - Writes the final markdown performance report.

## 7. Main Outputs
- Trained model: `gateway/ids/models/ids_model.joblib`
- Metadata: `gateway/ids/models/model_metadata.json`
- Single benchmark report: `gateway/ids/logs/multi_sensor_ip_eval.json`
- Matrix summary: `gateway/ids/logs/ip_benchmark_matrix_summary.json`
- Matrix markdown report: `gateway/ids/logs/model_performance_report.md`
- Offline eval outputs: `gateway/ids/output/ids_eval/*`

## 8. Troubleshooting
- If fake sensor scripts were changed but behavior does not change:
  - rebuild sensor images (`docker compose build ...`) before running tests.
- If traffic from sensors is missing:
  - avoid `BROKER_HOST=127.0.0.1` inside fake sensor containers.
  - use host-reachable IP (for example `172.31.217.41`).
- If `docker logs` is noisy from old runs:
  - recreate service with `--force-recreate` before new test.

## 9. Quick Run Checklist
1. Build sensors.
2. Start/recreate `ids-gateway`.
3. Run benchmark script.
4. Check JSON and markdown reports in `gateway/ids/logs`.
