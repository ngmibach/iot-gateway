#!/bin/bash

HOST="10.185.90.215"
PORT="8883"
USERNAME="sensor3"
PASSWORD="admin"
DEVICE_ID="sensor3"

TOPIC="sensors/${DEVICE_ID}/process"

CAFILE="./ca.crt"
CERT="./client.crt"
KEY="./client.key"

SLEEP_INTERVAL=1

# Paths
TEMP_JSON="temp_message.json"
ENCRYPTED_JSON="encrypted_message.json"
KEY_FILE="secret.key"

# Function to generate UUID
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

while true; do
    UUID=$(generate_uuid)

    TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%S.%3NZ")

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
  }
}
EOF

    python3 py_encrypt.py encrypt "$TEMP_JSON" --output "$ENCRYPTED_JSON" --key-file "$KEY_FILE"

    FERNET_KEY=$(tr -d '\n\r ' < "$KEY_FILE")

    jq --arg newkey "$FERNET_KEY" '
        .key = $newkey
    ' "$ENCRYPTED_JSON" > final_message.json

    mosquitto_pub -h "$HOST" -p "$PORT" \
        -u "$USERNAME" -P "$PASSWORD" \
        -t "$TOPIC" \
        -m "$(cat final_message.json)" \
        --cafile "$CAFILE" \
        --cert "$CERT" \
        --key "$KEY"

    echo "Published encrypted message with id: $UUID | Key embedded"

    sleep "$SLEEP_INTERVAL"
done