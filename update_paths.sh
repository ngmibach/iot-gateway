#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"

REPO_ROOT="$SCRIPT_DIR"

echo "Current checkout directory: $REPO_ROOT"


mapfile -t FILES < <(
  find "$REPO_ROOT" -path '*/data/*' -prune -o \
       -type d -name 'workflows' -print 2>/dev/null \
    | while IFS= read -r wfdir; do
        find "$wfdir" -maxdepth 1 -type f \( -name '*.yaml' -o -name '*.yml' \) 2>/dev/null || true
      done
)

if [[ ${#FILES[@]} -eq 0 ]]; then
  echo "No .yaml/.yml files found under any 'workflows' directory. Nothing to do."
  exit 0
fi

echo "Files that will be updated:"
printf '  %s\n' "${FILES[@]}"
echo

for f in "${FILES[@]}"; do
  sed -i -E 's|(-[[:space:]]+)/[^:]+/iot-gateway|\1'"$REPO_ROOT"'|g' "$f"

  if grep -q 'Fake_Sensor' "$f" 2>/dev/null; then
    sed -i -E 's|/[^:]+/Fake_Sensor/sensor([0-9])|'"$REPO_ROOT"'/fake_sensor/build/sensor\1|g' "$f"
    sed -i 's|/[^: ]*/Fake_Sensor/server_certs|'"$REPO_ROOT"'/gateway/certs|g' "$f"
  fi
done
