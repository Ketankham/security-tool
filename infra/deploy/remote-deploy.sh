#!/usr/bin/env bash
# Runs ON the Hetzner server, from /opt/sentinel, invoked by
# .github/workflows/deploy.yml after it has copied over:
#   sentinel-images.tar.gz  docker-compose.prod.yml  remote-deploy.sh  edge/
#
# Required env (passed through from GitHub secrets):
#   KMS_MASTER_KEY  API_SECRET_KEY  POSTGRES_PASSWORD
# Optional env:
#   ANTHROPIC_API_KEY  SITE_DOMAIN (default accsysn.duckdns.org)
#
# Never touches /opt/accsys (the accounting app). It only adds/updates the
# shared Caddy proxy in /opt/edge and the Sentinel stack in /opt/sentinel.
set -euo pipefail

APP_DIR=/opt/sentinel
EDGE_DIR=/opt/edge
COMPOSE=(docker compose -f "$APP_DIR/docker-compose.prod.yml" --project-directory "$APP_DIR")
SITE_DOMAIN="${SITE_DOMAIN:-accsysn.duckdns.org}"

log() { echo "==> $*"; }
die() { echo "ERROR: $*" >&2; exit 1; }

cd "$APP_DIR"

# --- 1. Validate secrets -----------------------------------------------------
: "${KMS_MASTER_KEY:?KMS_MASTER_KEY secret is not set in the GitHub repo}"
: "${API_SECRET_KEY:?API_SECRET_KEY secret is not set in the GitHub repo}"
: "${POSTGRES_PASSWORD:?POSTGRES_PASSWORD secret is not set in the GitHub repo}"

# Goes into a postgres:// URL unescaped, so keep it URL-safe.
[[ "$POSTGRES_PASSWORD" =~ ^[A-Za-z0-9_-]+$ ]] \
  || die "POSTGRES_PASSWORD may only contain letters, digits, '-' and '_' (generate with: openssl rand -hex 24)"

# A Fernet key is urlsafe-base64 of exactly 32 bytes = 44 chars ending in '='.
[[ "$KMS_MASTER_KEY" =~ ^[A-Za-z0-9_-]{43}=$ ]] \
  || die "KMS_MASTER_KEY is not a valid Fernet key (generate with: python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\")"

# Every stored persona credential is encrypted under this key. If the secret
# is ever changed by accident, all saved logins become undecryptable — so pin
# its fingerprint on first deploy and refuse to start with a different key.
KMS_FP="$(printf '%s' "$KMS_MASTER_KEY" | sha256sum | cut -d' ' -f1)"
if [[ -f "$APP_DIR/.kms_fingerprint" ]]; then
  [[ "$(cat "$APP_DIR/.kms_fingerprint")" == "$KMS_FP" ]] || die \
    "KMS_MASTER_KEY differs from the key this server was first deployed with. Existing encrypted credentials would become unreadable. Restore the original secret, or — only if you really mean to rotate it and accept losing stored persona credentials — delete $APP_DIR/.kms_fingerprint on the server and redeploy."
else
  printf '%s\n' "$KMS_FP" > "$APP_DIR/.kms_fingerprint"
  log "Pinned KMS_MASTER_KEY fingerprint (first deploy)."
fi

# --- 2. Write .env (rewritten each deploy: GitHub secrets are the source of truth)
umask 077
cat > "$APP_DIR/.env" <<EOF
ENVIRONMENT=production
POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
KMS_MASTER_KEY=${KMS_MASTER_KEY}
API_SECRET_KEY=${API_SECRET_KEY}
ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY:-}
CORS_ALLOW_ORIGINS=https://${SITE_DOMAIN}
EOF
umask 022

# --- 3. Load images ----------------------------------------------------------
log "Loading images..."
docker load < "$APP_DIR/sentinel-images.tar.gz"
rm -f "$APP_DIR/sentinel-images.tar.gz"

# --- 4. Data services + migrations --------------------------------------------
log "Starting postgres + redis..."
"${COMPOSE[@]}" up -d --wait --wait-timeout 120 postgres redis

log "Running database migrations..."
"${COMPOSE[@]}" run --rm --no-deps api \
  alembic -c packages/db/alembic.ini upgrade head

# --- 5. App services -----------------------------------------------------------
log "Starting api, worker, web..."
"${COMPOSE[@]}" up -d --remove-orphans --wait --wait-timeout 180

# --- 6. Shared Caddy proxy (/opt/edge) -------------------------------------------
log "Updating shared reverse proxy in $EDGE_DIR..."
mkdir -p "$EDGE_DIR/conf"
cp "$APP_DIR/edge/docker-compose.yml" "$EDGE_DIR/docker-compose.yml"
cp "$APP_DIR/edge/conf/Caddyfile" "$EDGE_DIR/conf/Caddyfile"
printf 'SITE_DOMAIN=%s\n' "$SITE_DOMAIN" > "$EDGE_DIR/.env"

EDGE=(docker compose -f "$EDGE_DIR/docker-compose.yml" --project-directory "$EDGE_DIR")

if [[ -z "$("${EDGE[@]}" ps -q caddy 2>/dev/null)" ]]; then
  # First start: make sure nothing else (e.g. a stray nginx/apache) holds 80/443,
  # otherwise Caddy would crash-loop silently.
  for port in 80 443; do
    if ss -ltnH "sport = :$port" | grep -q .; then
      die "Port $port is already in use on this server ($(ss -ltnpH "sport = :$port" | head -1)). Free it, then redeploy."
    fi
  done
  "${EDGE[@]}" up -d
else
  "${EDGE[@]}" up -d
  # Picks up Caddyfile changes without dropping connections.
  "${EDGE[@]}" exec -T caddy caddy reload --config /etc/caddy/Caddyfile --adapter caddyfile \
    || "${EDGE[@]}" restart caddy
fi

# --- 7. Smoke checks ----------------------------------------------------------------
log "Smoke checks..."
curl -fsS --retry 10 --retry-delay 3 --retry-all-errors http://127.0.0.1:8100/healthz >/dev/null \
  || die "API not healthy on 127.0.0.1:8100"
curl -fsS --retry 10 --retry-delay 3 --retry-all-errors -o /dev/null http://127.0.0.1:3100/security \
  || die "Web not healthy on 127.0.0.1:3100"
# Through Caddy. TLS may still be provisioning on the very first deploy, so
# this is a warning, not a failure.
if curl -fsS --retry 10 --retry-delay 3 --retry-all-errors -o /dev/null \
     "https://${SITE_DOMAIN}/security/api/healthz"; then
  log "Live: https://${SITE_DOMAIN}/security"
else
  echo "WARNING: https://${SITE_DOMAIN}/security/api/healthz not reachable yet (first-time certificate issuance can take a minute; check: docker logs edge-caddy-1)." >&2
fi

docker image prune -f >/dev/null
log "Done."
