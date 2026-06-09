#!/bin/sh
set -e

GITEA_URL="${GITEA_INTERNAL_URL:-http://172.17.0.1:5000}"
ADMIN_USER="${GITEA_ADMIN_USER:-admin}"
ADMIN_PASS="${GITEA_ADMIN_PASSWORD:-admin}"
ADMIN_EMAIL="${GITEA_ADMIN_EMAIL:-admin@localhost}"
REPO_NAME="${GITEA_SEED_REPO:-actions}"
GITEA_CONTAINER="${GITEA_CONTAINER_NAME:-gitea}"
CONTENT_DIR="${CONTENT_DIR:-/content}"

REGISTRY="${GITEA_REGISTRY:-localhost:5000}"
RUNNER_IMAGE="${REGISTRY}/admin/gitea/runner-images:ubuntu-latest"

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

ensure_docker_insecure_config() {
  mkdir -p /etc/docker
  cat > /etc/docker/daemon.json <<'J'
{
  "insecure-registries": [
    "172.17.0.1:5000",
    "localhost:5000",
    "127.0.0.1:5000"
  ]
}
J
  echo "[gitea-seed] Wrote /etc/docker/daemon.json with insecure-registries for 172.17.0.1:5000, localhost:5000, 127.0.0.1:5000"
  echo "[gitea-seed] Current /etc/docker/daemon.json inside gitea-seed container:"
  cat /etc/docker/daemon.json
}

build_and_push_runner_image() {
  echo "[gitea-seed] Ensuring custom runner image is available in Gitea registry..."
  echo "[gitea-seed]   Target: $RUNNER_IMAGE"

  ensure_docker_insecure_config

  local build_ctx=""
  if [ -d "/build-context/gitea-action-latest" ] && [ -f "/build-context/gitea-action-latest/Dockerfile" ]; then
    build_ctx="/build-context/gitea-action-latest"
    echo "[gitea-seed] Using mounted build context: $build_ctx"
  elif [ -f "/runner/action/Dockerfile" ]; then
    build_ctx=$(mktemp -d)
    cp "/runner/action/Dockerfile" "$build_ctx/Dockerfile"
    echo "[gitea-seed] Using bundled Dockerfile (copied to temp context $build_ctx)"
  else
    echo "[gitea-seed] WARNING: Action image build context not found at /build-context/gitea-action-latest (or no Dockerfile)."
    echo "[gitea-seed]          The gitea-seed service needs this volume mount (already added to docker-compose.yaml):"
    echo "[gitea-seed]            - ./build/gitea/action_latest:/build-context/gitea-action-latest:ro"
    echo "[gitea-seed]          (The seeder image also bakes in a copy as fallback via its own Dockerfile.)"
    echo "[gitea-seed]          Skipping runner image push to registry."
    return 1
  fi

  echo "[gitea-seed] Logging into container registry at $REGISTRY ..."
  if ! docker login "$REGISTRY" -u "$ADMIN_USER" -p "$ADMIN_PASS" >/dev/null 2>&1; then
    docker login "http://$REGISTRY" -u "$ADMIN_USER" -p "$ADMIN_PASS" >/dev/null 2>&1 || true
  fi

  echo "[gitea-seed] Building image (this can take a few minutes) ..."
  if ! docker build --progress=plain -t "$RUNNER_IMAGE" "$build_ctx"; then
    echo "[gitea-seed] ERROR: docker build failed" >&2
    [ "$build_ctx" != "/build-context/gitea-action-latest" ] && rm -rf "$build_ctx" || true
    return 1
  fi
  [ "$build_ctx" != "/build-context/gitea-action-latest" ] && rm -rf "$build_ctx" || true

  echo "[gitea-seed] Pushing $RUNNER_IMAGE to ${REGISTRY}/admin ..."
  if ! docker push "$RUNNER_IMAGE"; then
    echo "[gitea-seed] ERROR: docker push failed (verify the host or internal dockerd has the insecure-registries above, and that Gitea container registry is enabled)." >&2
    return 1
  fi

  echo "[gitea-seed] Successfully pushed runner image."
}

echo "[gitea-seed] Workflows content pushed. Now ensuring the custom runner image (with Docker pre-installed) is in the registry under admin/..."

if build_and_push_runner_image; then
  echo "[gitea-seed] Runner image ready at $RUNNER_IMAGE (workflows using runs-on: ubuntu-system or explicit container: image should now be able to pull it)."
else
  echo "[gitea-seed] WARNING: Runner image build/push step failed or was skipped."
  echo "[gitea-seed]          Workflows that require the container image may fail until this succeeds."
fi

echo "[gitea-seed] Done. Workflows should now be available in Gitea repo '$ADMIN_USER/$REPO_NAME'."
rm -rf "$TMP_DIR" || true

exit 0
