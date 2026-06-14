#!/bin/bash

HOST="${HOST:-172.31.217.41}"
PORT="${PORT:-8883}"
USERNAME="${USERNAME:-sensor4}"
PASSWORD="${PASSWORD:-admin}"
DEVICE_ID="${DEVICE_ID:-sensor4}"
USE_TLS="${USE_TLS:-1}"

TOPIC="sensors/${DEVICE_ID}/process"

CAFILE="./ca.crt"
CERT="./client.crt"
KEY="./client.key"
SLEEP_INTERVAL="${SLEEP_INTERVAL:-1}"

# Test modes:
# - continuous: publish forever (default)
# - e2e_ddos: benign -> attack -> benign (fixed duration)
TEST_MODE="${TEST_MODE:-continuous}"

# E2E durations (seconds)
BENIGN_DURATION="${BENIGN_DURATION:-15}"
ATTACK_DURATION="${ATTACK_DURATION:-15}"

# Attack tuning for MQTT/TCP flood profile
ATTACK_BURST="${ATTACK_BURST:-10}"
ATTACK_SLEEP="${ATTACK_SLEEP:-0.02}"
ATTACK_TOPIC_JITTER="${ATTACK_TOPIC_JITTER:-1}"
ATTACK_LARGE_PAYLOAD="${ATTACK_LARGE_PAYLOAD:-1}"

# Paths
TEMP_JSON="temp_message.json"
ENCRYPTED_JSON="encrypted_message.json"
KEY_FILE="secret.key"

PHASE="benign"
PHASE_START_TS="$(date +%s)"

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

update_phase() {
    if [[ "$TEST_MODE" != "e2e_ddos" ]]; then
        PHASE="benign"
        return 0
    fi

    local now elapsed
    now="$(date +%s)"
    elapsed=$((now - PHASE_START_TS))

    case "$PHASE" in
        benign)
            if (( elapsed >= BENIGN_DURATION )); then
                PHASE="attack"
                PHASE_START_TS="$now"
                echo "[E2E] Switch phase -> ATTACK"
            fi
            ;;
        attack)
            if (( elapsed >= ATTACK_DURATION )); then
                PHASE="recovery"
                PHASE_START_TS="$now"
                echo "[E2E] Switch phase -> RECOVERY"
            fi
            ;;
        recovery)
            if (( elapsed >= BENIGN_DURATION )); then
                echo "[E2E] Completed benign->attack->recovery. Exit."
                exit 0
            fi
            ;;
    esac
}

phase_sleep() {
    if [[ "$PHASE" == "attack" ]]; then
        sleep "$ATTACK_SLEEP"
    else
        sleep "$SLEEP_INTERVAL"
    fi
}

phase_burst_count() {
    if [[ "$PHASE" == "attack" ]]; then
        echo "$ATTACK_BURST"
    else
        echo "1"
    fi
}

phase_topic() {
    if [[ "$PHASE" == "attack" && "$ATTACK_TOPIC_JITTER" == "1" ]]; then
        echo "${TOPIC}/flood/$((RANDOM % 10000))"
    else
        echo "$TOPIC"
    fi
}

while true; do
    update_phase

    BURST_COUNT="$(phase_burst_count)"
    ACTIVE_TOPIC="$(phase_topic)"

    # In attack phase, run multiple publishes per loop to emulate burst/flood behavior.
    for (( burst_idx=1; burst_idx<=BURST_COUNT; burst_idx++ )); do
        UUID=$(generate_uuid)
        TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%S.%3NZ")

        # ==================== RANDOM VALUES ====================
        if [[ "$PHASE" == "attack" ]]; then
            TEMP_CHAMBER=$(awk -v min=1350 -v max=1550 'BEGIN{srand(); printf "%.1f", min+rand()*(max-min)}')
        else
            TEMP_CHAMBER=$(awk -v min=1410 -v max=1435 'BEGIN{srand(); printf "%.1f", min+rand()*(max-min)}')
        fi

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

        if [[ "$PHASE" == "attack" && "$ATTACK_LARGE_PAYLOAD" == "1" ]]; then
            EXTRA_BLOB=$(head -c 384 </dev/urandom | base64 | tr -d '\n')
        else
            EXTRA_BLOB=""
        fi

        # ==================== BUILD JSON ====================
        cat > "$TEMP_JSON" <<JSON_EOF
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
  "testPhase": "$PHASE",
  "floodSequence": $burst_idx,
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
    "attack_blob": "$EXTRA_BLOB"
  }
}
JSON_EOF

        python3 py_encrypt.py encrypt "$TEMP_JSON" --output "$ENCRYPTED_JSON" --key-file "$KEY_FILE"

        FERNET_KEY=$(tr -d '\n\r ' < "$KEY_FILE")

        jq --arg newkey "$FERNET_KEY" '.key = $newkey' "$ENCRYPTED_JSON" > final_message.json

        if [[ "$USE_TLS" == "1" ]]; then
            mosquitto_pub -h "$HOST" -p "$PORT" \
                -u "$USERNAME" -P "$PASSWORD" \
                -t "$ACTIVE_TOPIC" \
                -m "$(cat final_message.json)" \
                --cafile "$CAFILE" \
                --cert "$CERT" \
                --key "$KEY"
        else
            mosquitto_pub -h "$HOST" -p "$PORT" \
                -u "$USERNAME" -P "$PASSWORD" \
                -t "$ACTIVE_TOPIC" \
                -m "$(cat final_message.json)"
        fi

        echo "[$PHASE] Published encrypted message id=$UUID topic=$ACTIVE_TOPIC burst=$burst_idx/$BURST_COUNT"
    done

    phase_sleep
done
