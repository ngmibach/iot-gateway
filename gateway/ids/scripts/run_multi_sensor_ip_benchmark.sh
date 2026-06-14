#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
FAKE_COMPOSE="${ROOT_DIR}/fake_sensor/docker-compose.yaml"
GATEWAY_COMPOSE="${ROOT_DIR}/gateway/docker-compose.yaml"
LOG_DIR="${ROOT_DIR}/gateway/ids/logs"
OUT_LOG="${OUT_LOG:-${LOG_DIR}/multi_sensor_ids_full.log}"
OUT_JSON="${OUT_JSON:-${LOG_DIR}/multi_sensor_ip_eval.json}"

BROKER_HOST="${BROKER_HOST:-172.31.217.41}"
BROKER_PORT="${BROKER_PORT:-1883}"
USE_TLS="${USE_TLS:-0}"
BENIGN_DURATION="${BENIGN_DURATION:-8}"
ATTACK_DURATION="${ATTACK_DURATION:-14}"
ATTACK_DEVICES="${ATTACK_DEVICES:-sensor1,sensor3}"
ATTACK_LEVEL="${ATTACK_LEVEL:-heavy}"
SENSOR_LIST="${SENSOR_LIST:-sensor1,sensor2,sensor3,sensor4}"

contains_csv_item() {
  local csv="$1"
  local item="$2"
  local normalized=",${csv// /},"
  [[ "${normalized}" == *",${item},"* ]]
}

sensor_run_mode() {
  local sensor="$1"
  if contains_csv_item "${ATTACK_DEVICES}" "${sensor}"; then
    echo "e2e_ddos"
  else
    echo "continuous"
  fi
}

sensor_attack_tuning() {
  local sensor="$1"
  if [[ "$(sensor_run_mode "${sensor}")" != "e2e_ddos" ]]; then
    echo "1 0.80 0 0"
    return 0
  fi

  case "${ATTACK_LEVEL}" in
    light)
      echo "4 0.08 1 0"
      ;;
    heavy)
      echo "12 0.02 1 1"
      ;;
    mixed)
      if [[ "${sensor}" == "sensor1" ]]; then
        echo "7 0.05 1 1"
      else
        echo "4 0.08 1 0"
      fi
      ;;
    *)
      echo "12 0.02 1 1"
      ;;
  esac
}

launch_sensor() {
  local sensor="$1"
  local mode burst sleep_s jitter payload
  mode="$(sensor_run_mode "${sensor}")"
  read -r burst sleep_s jitter payload < <(sensor_attack_tuning "${sensor}")

  docker compose -f "${FAKE_COMPOSE}" run -d --rm --name "idsbench_${sensor}" \
    -e HOST="${BROKER_HOST}" -e PORT="${BROKER_PORT}" -e USE_TLS="${USE_TLS}" \
    -e TEST_MODE="${mode}" -e BENIGN_DURATION="${BENIGN_DURATION}" -e ATTACK_DURATION="${ATTACK_DURATION}" \
    -e SLEEP_INTERVAL=1.0 -e ATTACK_BURST="${burst}" -e ATTACK_SLEEP="${sleep_s}" \
    -e ATTACK_TOPIC_JITTER="${jitter}" -e ATTACK_LARGE_PAYLOAD="${payload}" \
    "${sensor}" >/dev/null
}

IFS=',' read -r -a SENSOR_ARRAY <<< "${SENSOR_LIST}"
SENSOR_CONTAINERS=()
for sensor in "${SENSOR_ARRAY[@]}"; do
  sensor_trimmed="${sensor// /}"
  if [[ -n "${sensor_trimmed}" ]]; then
    SENSOR_CONTAINERS+=("idsbench_${sensor_trimmed}")
  fi
done

cleanup() {
  for cname in "${SENSOR_CONTAINERS[@]}"; do
    docker rm -f "${cname}" >/dev/null 2>&1 || true
  done
}
trap cleanup EXIT

mkdir -p "${LOG_DIR}"

start_iso="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

echo "[BENCH] restart ids-gateway"
docker compose -f "${GATEWAY_COMPOSE}" restart ids-gateway >/dev/null
sleep 3

echo "[BENCH] launch multi-sensor traffic (attack_devices=${ATTACK_DEVICES}, attack_level=${ATTACK_LEVEL})"
for sensor in "${SENSOR_ARRAY[@]}"; do
  sensor_trimmed="${sensor// /}"
  [[ -n "${sensor_trimmed}" ]] || continue
  launch_sensor "${sensor_trimmed}"
done

run_seconds=$(( BENIGN_DURATION + ATTACK_DURATION + BENIGN_DURATION + 5 ))
echo "[BENCH] running for ${run_seconds}s"
sleep "${run_seconds}"

echo "[BENCH] stop continuous benign senders"
for sensor in "${SENSOR_ARRAY[@]}"; do
  sensor_trimmed="${sensor// /}"
  [[ -n "${sensor_trimmed}" ]] || continue
  if [[ "$(sensor_run_mode "${sensor_trimmed}")" == "continuous" ]]; then
    docker rm -f "idsbench_${sensor_trimmed}" >/dev/null 2>&1 || true
  fi
done

sleep 2

echo "[BENCH] collect ids logs"
docker logs --since "${start_iso}" iot-ids-gateway > "${OUT_LOG}" 2>&1 || true

echo "[BENCH] evaluate IP-level detection"
python3 "${ROOT_DIR}/gateway/ids/scripts/eval_multi_sensor_ip_detection.py" \
  --log "${OUT_LOG}" \
  --attack-devices "${ATTACK_DEVICES}" \
  --output-json "${OUT_JSON}"

echo "[BENCH] completed"
echo "[BENCH] log=${OUT_LOG}"
echo "[BENCH] report=${OUT_JSON}"
