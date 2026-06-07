#!/bin/sh
set -e

GITEA_URL="${GITEA_INTERNAL_URL:-http://172.17.0.1:5000}"
ADMIN_USER="${GITEA_ADMIN_USER:-admin}"
ADMIN_PASS="${GITEA_ADMIN_PASSWORD:-admin}"
ADMIN_EMAIL="${GITEA_ADMIN_EMAIL:-admin@localhost}"
REPO_NAME="${GITEA_SEED_REPO:-actions}"
GITEA_CONTAINER="${GITEA_CONTAINER_NAME:-gitea}"
CONTENT_DIR="${CONTENT_DIR:-/content}"

resolve_gitea_container() {
  local candidate="$1"

  if docker exec "$candidate" true >/dev/null 2>&1; then
    echo "$candidate"
    return 0
  fi

  local found
  found=$(docker ps --filter "label=com.docker.compose.service=gitea" --format '{{.Names}}' 2>/dev/null | head -1)
  if [ -n "$found" ] && docker exec "$found" true >/dev/null 2>&1; then
    echo "$found"
    return 0
  fi

  found=$(docker ps --filter "label=io.docker.compose.service=gitea" --format '{{.Names}}' 2>/dev/null | head -1)
  if [ -n "$found" ] && docker exec "$found" true >/dev/null 2>&1; then
    echo "$found"
    return 0
  fi

  echo "$candidate"
}

GITEA_CONTAINER=$(resolve_gitea_container "$GITEA_CONTAINER")

if [ "$GITEA_CONTAINER" != "${GITEA_CONTAINER_NAME:-gitea}" ]; then
  echo "[gitea-seed] Resolved gitea container name via labels: $GITEA_CONTAINER"
fi

echo "[gitea-seed] Waiting for Gitea to be ready at $GITEA_URL ..."
ATTEMPTS=0
MAX_ATTEMPTS=60
until curl -fsS "$GITEA_URL/api/v1/version" >/dev/null 2>&1 || curl -fsS "$GITEA_URL/" >/dev/null 2>&1; do
  ATTEMPTS=$((ATTEMPTS + 1))
  if [ "$ATTEMPTS" -ge "$MAX_ATTEMPTS" ]; then
    echo "[gitea-seed] ERROR: Gitea did not become ready in time" >&2
    exit 1
  fi
  sleep 2
done
echo "[gitea-seed] Gitea is responding."

echo "[gitea-seed] Ensuring admin user '$ADMIN_USER' exists..."
CREATE_USER_OUTPUT=$(docker exec "$GITEA_CONTAINER" gitea admin user create \
  --username "$ADMIN_USER" \
  --password "$ADMIN_PASS" \
  --email "$ADMIN_EMAIL" \
  --admin \
  --must-change-password=false 2>&1) || true

if echo "$CREATE_USER_OUTPUT" | grep -qi "already exist\|user.*exist"; then
  echo "[gitea-seed] Admin user already exists, continuing."
elif echo "$CREATE_USER_OUTPUT" | grep -qi "no such container"; then
  echo "[gitea-seed] WARNING: Could not 'docker exec' into the gitea container (name: $GITEA_CONTAINER)."
  echo "[gitea-seed]          Admin user may already exist; continuing with API operations."
else
  [ -n "$CREATE_USER_OUTPUT" ] && echo "$CREATE_USER_OUTPUT"
  echo "[gitea-seed] Admin user creation step finished."
fi

echo "[gitea-seed] Ensuring repository '$ADMIN_USER/$REPO_NAME' exists..."
CREATE_RESP=$(curl -sS -w "\n%{http_code}" -o /tmp/create_repo.json \
  -u "$ADMIN_USER:$ADMIN_PASS" \
  -X POST \
  -H "Content-Type: application/json" \
  -H "Accept: application/json" \
  -d "{\"name\":\"$REPO_NAME\",\"private\":true,\"description\":\"Gitea Actions workflows\",\"auto_init\":false}" \
  "$GITEA_URL/api/v1/user/repos" 2>/dev/null || echo "000")

HTTP_CODE=$(echo "$CREATE_RESP" | tail -n1)
if [ "$HTTP_CODE" = "201" ]; then
  echo "[gitea-seed] Repository created."
elif [ "$HTTP_CODE" = "409" ] || grep -qi "already exist" /tmp/create_repo.json 2>/dev/null; then
  echo "[gitea-seed] Repository already exists."
else
  echo "[gitea-seed] Repo creation HTTP $HTTP_CODE (may be ok if exists):"
  cat /tmp/create_repo.json || true
fi

TMP_DIR=$(mktemp -d)
REPO_DIR="$TMP_DIR/repo"
GIT_URL="http://${ADMIN_USER}:${ADMIN_PASS}@172.17.0.1:5000/${ADMIN_USER}/${REPO_NAME}.git"

echo "[gitea-seed] Preparing to push content from $CONTENT_DIR to $REPO_NAME ..."

if git clone --quiet "$GIT_URL" "$REPO_DIR" 2>/dev/null; then
  echo "[gitea-seed] Cloned existing repository."
else
  echo "[gitea-seed] Repository is empty or new; initializing locally."
  mkdir -p "$REPO_DIR"
  git init -q "$REPO_DIR"
  git -C "$REPO_DIR" remote add origin "$GIT_URL" 2>/dev/null || true
fi

cd "$REPO_DIR"

echo "[gitea-seed] Copying content..."
find "$CONTENT_DIR" -mindepth 1 -maxdepth 1 -exec cp -a {} . \;

if [ -z "$(git status --porcelain 2>/dev/null)" ]; then
  echo "[gitea-seed] No changes detected; nothing to push."
else
  git config user.name "Gitea Seeder"
  git config user.email "$ADMIN_EMAIL"
  git add .
  git commit -m "Seed/update Gitea Actions from host (gitea_actions folder)"
  if git push -u origin main 2>/dev/null || git push -u origin master 2>/dev/null; then
    echo "[gitea-seed] Push successful."
  else
    git push -u origin HEAD:main 2>/dev/null || git push -f origin HEAD:main
    echo "[gitea-seed] Push completed (forced branch creation if needed)."
  fi
fi

echo "[gitea-seed] Done. Workflows should now be available in Gitea repo '$ADMIN_USER/$REPO_NAME'."
rm -rf "$TMP_DIR" || true
exit 0
