#!/bin/sh

set -eu

IP_SRC="/config/allowed-ips.txt"
ACL_SRC="/config/acl"
DST="/textfile/allowed_ips.prom"
TMP="${DST}.tmp"

echo "sync-config: starting, watching ${IP_SRC} and ${ACL_SRC}"

while true; do
  {
    # Allowed IPs
    while IFS= read -r line || [ -n "$line" ]; do
      ip=$(printf '%s' "$line" | tr -d ' \t\r\n')
      [ -z "$ip" ] && continue
      printf 'allowed_ip{ip="%s"} 1\n' "$ip"
    done < "$IP_SRC"

    cnt=$(grep -cve '^[[:space:]]*$' "$IP_SRC" 2>/dev/null || echo 0)
    printf 'allowed_ip_count %s\n' "$cnt"

    # Mosquitto ACL
    if [ -f "$ACL_SRC" ]; then
      current_user=""
      while IFS= read -r line || [ -n "$line" ]; do
        line=$(printf '%s' "$line" | tr -d '\r')
        [ -z "$line" ] && continue
        case "$line" in
          user\ *)
            current_user=$(printf '%s' "$line" | cut -d' ' -f2- | tr -d ' \t')
            ;;
          topic\ *)
            fields=$(printf '%s' "$line" | cut -d' ' -f2-)
            perm=$(printf '%s' "$fields" | cut -d' ' -f1)
            topic=$(printf '%s' "$fields" | cut -d' ' -f2- | tr -d '\r' | sed 's/^[ \t]*//;s/[ \t]*$//')
            if [ "$perm" = "none" ]; then
              topic="none"
            fi
            if [ -n "$current_user" ] && [ -n "$topic" ]; then
              printf 'acl{user="%s",topic="%s",permission="%s"} 1\n' "$current_user" "$topic" "$perm"
            fi
            ;;
        esac
      done < "$ACL_SRC"
    fi
  } > "$TMP" && mv "$TMP" "$DST"

  mkdir -p /var/log/iot-gateway
  allowed_ips=$(cat "$IP_SRC" | grep -v '^[[:space:]]*$' | jq -R -s -c 'split("\n") | map(select(. != ""))' 2>/dev/null || echo '[]')
  acl_state=$(/usr/local/bin/acl_to_json.py 2>/dev/null || echo '{}')
  echo "{\"@timestamp\":\"$(date -Iseconds)\",\"event_type\":\"state_snapshot\",\"state_type\":\"allowed_ips_acl\",\"allowed_ips\":$allowed_ips,\"acl\":$acl_state}" >> /var/log/iot-gateway/gateway-state.log

  sleep 15
done
