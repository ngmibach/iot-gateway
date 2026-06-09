#!/bin/shSSS

set -eu

SRC="/config/allowed-ips.txt"
DST="/textfile/allowed_ips.prom"
TMP="${DST}.tmp"

echo "ip-allow: starting, watching ${SRC}"

while true; do
  {
    while IFS= read -r line || [ -n "$line" ]; do
      ip=$(printf '%s' "$line" | tr -d ' \t\r\n')
      [ -z "$ip" ] && continue
      printf 'allowed_ip{ip="%s"} 1\n' "$ip"
    done < "$SRC"

    cnt=$(grep -cve '^[[:space:]]*$' "$SRC" 2>/dev/null || echo 0)
    printf 'allowed_ip_count %s\n' "$cnt"
  } > "$TMP" && mv "$TMP" "$DST"

  sleep 15
done
