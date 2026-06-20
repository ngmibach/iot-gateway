#!/bin/bash

HOST="${HOST:-172.31.217.41}"
PORT="${PORT:-8883}"
USERNAME="${USERNAME:-sensor1}"
PASSWORD="${PASSWORD:-admin}"
DEVICE_ID="${DEVICE_ID:-sensor1}"

TOPIC="sensors/${DEVICE_ID}/process"

CAFILE="./ca.crt"
CERT="./client.crt"
KEY="./client.key"
SLEEP_INTERVAL="${SLEEP_INTERVAL:-0.01}"

# Attack-lite toggles (minimal deviation from sensor1 baseline)
ATTACK_LITE="${ATTACK_LITE:-1}"
ATTACK_BURST="${ATTACK_BURST:-3}"
ATTACK_SLEEP="${ATTACK_SLEEP:-0.02}"
ATTACK_TOPIC_JITTER="${ATTACK_TOPIC_JITTER:-1}"
ATTACK_LARGE_PAYLOAD="${ATTACK_LARGE_PAYLOAD:-1}"

# Attack-lite-v2 controls
ATTACK_CONN_CHURN="${ATTACK_CONN_CHURN:-1}"
CHURN_INTERVAL="${CHURN_INTERVAL:-12}"
UNAUTHORIZED_RATIO="${UNAUTHORIZED_RATIO:-0.2}"
UNAUTHORIZED_TOPICS="${UNAUTHORIZED_TOPICS:-sensors/sensor2/process,sensors/sensor3/process,sensors/sensor4/process}"

# Paths
TEMP_JSON="temp_message.json"
KEY_FILE="secret.key"
PUBLISH_COUNTER=0
CHURN_PROBE_COUNT=0

generate_uuid() {
    if command -v uuidgen >/dev/null 2>&1; then
        uuidgen
    else
        printf "%04x%04x-%04x-%04x-%04x-%04x%04x%04x" \
            $((RANDOM%65536)) $((RANDOM%65536)) \
            $((RANDOM%65536)) $((RANDOM%16384+16384)) \
            $((RANDOM%65536)) $((RANDOM%65536)) \
            $((RANDOM%65536)) $((RANDOM%65536))
    fi
}

is_unauthorized_publish() {
  if [[ "$ATTACK_LITE" != "1" ]]; then
    return 1
  fi

  awk -v r="$UNAUTHORIZED_RATIO" 'BEGIN {srand(); if (rand() < r) exit 0; exit 1}'
}

pick_unauthorized_topic() {
  local raw="$UNAUTHORIZED_TOPICS"
  IFS=',' read -r -a topic_pool <<< "$raw"
  echo "${topic_pool[$((RANDOM % ${#topic_pool[@]}))]}"
}

run_churn_probe() {
  if [[ "$ATTACK_LITE" != "1" || "$ATTACK_CONN_CHURN" != "1" ]]; then
    return 0
  fi

  if (( CHURN_INTERVAL <= 0 )); then
    return 0
  fi

  if (( PUBLISH_COUNTER % CHURN_INTERVAL != 0 )); then
    return 0
  fi

  local churn_topic="${TOPIC}/churn/$((RANDOM % 10000))"
  CHURN_PROBE_COUNT=$((CHURN_PROBE_COUNT + 1))
  mosquitto_pub -h "$HOST" -p "$PORT" \
    -u "$USERNAME" -P "$PASSWORD" \
    -t "$churn_topic" -n \
    --cafile "$CAFILE" \
    --cert "$CERT" \
    --key "$KEY" >/dev/null 2>&1

  echo "[attack_lite=$ATTACK_LITE] churn_probe count=$CHURN_PROBE_COUNT topic=$churn_topic"
}

while true; do
    BURST_COUNT=1
    ACTIVE_TOPIC="$TOPIC"
    ACTIVE_SLEEP="$SLEEP_INTERVAL"

    if [[ "$ATTACK_LITE" == "1" ]]; then
        BURST_COUNT="$ATTACK_BURST"
        ACTIVE_SLEEP="$ATTACK_SLEEP"
    fi

    for (( burst_idx=1; burst_idx<=BURST_COUNT; burst_idx++ )); do
      PUBLISH_COUNTER=$((PUBLISH_COUNTER + 1))
        UUID=$(generate_uuid)

        TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%S.%3NZ")

        IS_UNAUTHORIZED="0"
        if is_unauthorized_publish; then
          ACTIVE_TOPIC="$(pick_unauthorized_topic)"
          IS_UNAUTHORIZED="1"
        elif [[ "$ATTACK_LITE" == "1" && "$ATTACK_TOPIC_JITTER" == "1" ]]; then
          ACTIVE_TOPIC="${TOPIC}/flood/$((RANDOM % 10000))"
        else
          ACTIVE_TOPIC="$TOPIC"
        fi

        EXTRA_BLOB=""
        if [[ "$ATTACK_LITE" == "1" && "$ATTACK_LARGE_PAYLOAD" == "1" ]]; then
            EXTRA_BLOB=$(head -c 256 </dev/urandom | base64 | tr -d '\n')
        fi

        # ==================== RANDOM VALUES ====================
        TEMP_CHAMBER=$(awk -v min=1410 -v max=1435 'BEGIN{srand(); printf "%.1f", min+rand()*(max-min)}')
        TEMP_SETPOINT=1450.0
        TEMP_Z1=$(awk -v c="$TEMP_CHAMBER" 'BEGIN{printf "%.1f", c + (rand()-0.5)*8}')
        TEMP_Z2=$(awk -v c="$TEMP_CHAMBER" 'BEGIN{printf "%.1f", c + (rand()-0.5)*9}')
        TEMP_Z3=$(awk -v c="$TEMP_CHAMBER" 'BEGIN{printf "%.1f", c + (rand()-0.5)*7}')

        PRESS_CHAMBER=$(awk -v min=0.00070 -v max=0.00095 'BEGIN{srand(); printf "%.5f", min+rand()*(max-min)}')
        PRESS_SETPOINT=0.001
        PRESS_FOREVACUUM=$(awk -v min=10 -v max=15 'BEGIN{srand(); printf "%.1f", min+rand()*(max-min)}')
        DELTA_PRESS=$(awk -v min=0.08 -v max=0.22 'BEGIN{srand(); printf "%.2f", min+rand()*(max-min)}')

        GAS_ARGON=$(awk -v min=38 -v max=52 'BEGIN{srand(); printf "%.1f", min+rand()*(max-min)}')
        GAS_NITROGEN=$(awk -v min=0 -v max=2 'BEGIN{srand(); printf "%.1f", min+rand()*(max-min)}')
        GAS_HYDROGEN=$(awk -v min=6 -v max=11 'BEGIN{srand(); printf "%.1f", min+rand()*(max-min)}')

        POWER_TOTAL=$(awk -v min=38 -v max=47 'BEGIN{srand(); printf "%.1f", min+rand()*(max-min)}')
        POWER_Z1=$(awk -v p="$POWER_TOTAL" 'BEGIN{printf "%.1f", p*0.33 + (rand()-0.5)*2}')
        POWER_Z2=$(awk -v p="$POWER_TOTAL" 'BEGIN{printf "%.1f", p*0.33 + (rand()-0.5)*2}')
        POWER_Z3=$(awk -v p="$POWER_TOTAL" 'BEGIN{printf "%.1f", p*0.34 + (rand()-0.5)*2}')

        VACUUM_SPEED=$(awk -v min=92 -v max=99.9 'BEGIN{srand(); printf "%.1f", min+rand()*(max-min)}')
        CYCLE_ELAPSED=$((RANDOM % 18000 + 8000))
        CYCLE_REMAINING=$((RANDOM % 8000 + 2000))

        O2=$(awk -v min=0.3 -v max=1.8 'BEGIN{srand(); printf "%.1f", min+rand()*(max-min)}')
        DEWPOINT=$(awk -v min=-52 -v max=-44 'BEGIN{srand(); printf "%.1f", min+rand()*(max-min)}')
        VIBRATION=$(awk -v min=0.05 -v max=0.25 'BEGIN{srand(); printf "%.2f", min+rand()*(max-min)}')

        STAGES=("RAMP_UP" "HOLD" "COOL_DOWN" "PURGE" "STANDBY")
        SINTER_STAGE=${STAGES[$((RANDOM % 5))]}

        # ==================== BUILD JSON (with parameters) ====================
        cat > "$TEMP_JSON" <<EOF
{
  "batch": {
    "handlingUnit": null,
    "material": null,
    "name": "0",
    "productionOrder": null,
    "program": { "name": "UNKNOWN", "version": "UNKNOWN" }
  },
  "dataModel": { "id": "2", "state": "PRODUCTIVE" },
  "device": {
    "building": "UNKNOWN",
    "giai": "UNKNOWN",
    "id": "UNKNOWN",
    "level": "UNKNOWN",
    "location": "UNKNOWN",
    "machineCluster": "ALD VKU vacuum sintering",
    "machineName": "UNKNOWN",
    "mesId": "UNKNOWN",
    "organizationalUnit": "UNKNOWN",
    "plant": "UNKNOWN",
    "valueStream": "UNKOWN",
    "workCenter": "UNKNOWN",
    "workUnit": "UNKOWN"
  },
  "id": "$UUID",
  "timestamp": "$TIMESTAMP",
  "process": {
    "description": "UNKOWN",
    "id": "UNKNOW",
    "parameters": {
      "temperatureChamber": {"unit": "°C", "value": $TEMP_CHAMBER},
      "temperatureSetpoint": {"unit": "°C", "value": $TEMP_SETPOINT},
      "temperatureZone1": {"unit": "°C", "value": $TEMP_Z1},
      "temperatureZone2": {"unit": "°C", "value": $TEMP_Z2},
      "temperatureZone3": {"unit": "°C", "value": $TEMP_Z3},
      "pressureChamber": {"unit": "mbar", "value": $PRESS_CHAMBER},
      "pressureSetpoint": {"unit": "mbar", "value": $PRESS_SETPOINT},
      "pressureForevacuum": {"unit": "mbar", "value": $PRESS_FOREVACUUM},
      "deltaPressureMuffle": {"unit": "mbar", "value": $DELTA_PRESS},
      "gasFlowArgon": {"unit": "l/min", "value": $GAS_ARGON},
      "gasFlowNitrogen": {"unit": "l/min", "value": $GAS_NITROGEN},
      "gasFlowHydrogen": {"unit": "l/min", "value": $GAS_HYDROGEN},
      "powerHeatingTotal": {"unit": "kW", "value": $POWER_TOTAL},
      "powerHeatingZone1": {"unit": "kW", "value": $POWER_Z1},
      "powerHeatingZone2": {"unit": "kW", "value": $POWER_Z2},
      "powerHeatingZone3": {"unit": "kW", "value": $POWER_Z3},
      "vacuumPumpSpeed": {"unit": "%", "value": $VACUUM_SPEED},
      "cycleTimeElapsed": {"unit": "s", "value": $CYCLE_ELAPSED},
      "cycleTimeRemaining": {"unit": "s", "value": $CYCLE_REMAINING},
      "o2Concentration": {"unit": "ppm", "value": $O2},
      "dewPoint": {"unit": "°C", "value": $DEWPOINT},
      "vibrationLevel": {"unit": "mm/s", "value": $VIBRATION},
      "sinteringStage": {"unit": "", "value": "$SINTER_STAGE"}
    }
  },
  "station": {
    "clampingUnit": "unclamped",
    "name": "chamber"
  },
  "debug": {
    "attack_blob": "$EXTRA_BLOB",
    "attack_lite": "$ATTACK_LITE",
    "attack_conn_churn": "$ATTACK_CONN_CHURN",
    "is_unauthorized": "$IS_UNAUTHORIZED",
    "unauthorized_ratio": "$UNAUTHORIZED_RATIO",
    "burst": $BURST_COUNT,
    "burst_index": $burst_idx
  }
}
EOF

        python3 py_encrypt.py encrypt "$TEMP_JSON" --output final_message.json --key-file "$KEY_FILE"

        run_churn_probe

        mosquitto_pub -h "$HOST" -p "$PORT" \
            -u "$USERNAME" -P "$PASSWORD" \
            -t "$ACTIVE_TOPIC" \
            -m "$(cat final_message.json)" \
            --cafile "$CAFILE" \
            --cert "$CERT" \
            --key "$KEY"

        PUB_RC=$?

        if [[ "$IS_UNAUTHORIZED" == "1" ]]; then
          echo "[attack_lite=$ATTACK_LITE] unauthorized_attempt rc=$PUB_RC id=$UUID topic=$ACTIVE_TOPIC burst=$burst_idx/$BURST_COUNT"
        else
          echo "[attack_lite=$ATTACK_LITE] published rc=$PUB_RC id=$UUID topic=$ACTIVE_TOPIC burst=$burst_idx/$BURST_COUNT"
        fi
    done

    sleep "$ACTIVE_SLEEP"
done