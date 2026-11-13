#!/usr/bin/env bash
# Runs ON the Hetzner server, from /opt/sentinel, invoked by
# the `deploy` job in .github/workflows/ci.yml after it has copied over:
#   sentinel-images.tar.gz  docker-compose.prod.yml  remote-deploy.sh  edge/
#
# Optional env (GitHub secrets — all may be left unset):
#   KMS_MASTER_KEY  API_SECRET_KEY  POSTGRES_PASSWORD
#       Generated on the server on first deploy and kept in
#       /opt/sentinel/.secrets from then on. Set them only to supply your own
#       values; a supplied KMS key / DB password that differs from the stored
#       one aborts the deploy instead of silently breaking data.
#   DASHBOARD_PASSWORD
#       Password for https://<domain>/security (user: DASHBOARD_USER, default
#       "sentinel"). Generated on the server on first deploy and kept in
#       /opt/sentinel/.secrets when unset; setting the GitHub secret replaces it.
#   DASHBOARD_USER  ANTHROPIC_API_KEY  SITE_DOMAIN (default accsysn.duckdns.org)
#
# Never touches /opt/accsys (the accounting app). It only adds/updates the
# shared Caddy proxy in /opt/edge and the Sentinel stack in /opt/sentinel.
set -euo pipefail

APP_DIR=/opt/sentinel
EDGE_DIR=/opt/edge
SECRETS_FILE="$APP_DIR/.secrets"
COMPOSE=(docker compose -f "$APP_DIR/docker-compose.prod.yml" --project-directory "$APP_DIR")
SITE_DOMAIN="${SITE_DOMAIN:-accsysn.duckdns.org}"

log() { echo "==> $*"; }
die() { echo "ERROR: $*" >&2; exit 1; }

cd "$APP_DIR"

# --- 1. Resolve app secrets (stored on server > GitHub secret > generate) -----
umask 077

stored_secret() { grep -m1 "^$1=" "$SECRETS_FILE" 2>/dev/null | cut -d= -f2- || true; }
# Fernet key: urlsafe-base64 of 32 random bytes (44 chars ending in '=').
gen_fernet() { head -c 32 /dev/urandom | base64 | tr '+/' '-_' | tr -d '\n'; }
gen_hex() { head -c "$1" /dev/urandom | od -An -vtx1 | tr -d ' \n'; }
gen_password() { head -c 48 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | cut -c1-24; }

# If the database volume exists but the secrets file is gone, generating fresh
# values would lock the app out of Postgres and make every stored credential
# undecryptable. Stop and ask for the backup instead.
if [[ ! -f "$SECRETS_FILE" ]] && docker volume inspect sentinel_pgdata >/dev/null 2>&1; then
  die "$SECRETS_FILE is missing but the sentinel_pgdata volume exists. Restore the backed-up .secrets file to $SECRETS_FILE (or set KMS_MASTER_KEY/POSTGRES_PASSWORD secrets to the original values) and redeploy."
fi

# resolve NAME GENERATOR... — prints the value to use.
#   pinned: once stored, a different supplied value is an error (KMS key, DB password)
resolve() {
  local name="$1" mode="$2"; shift 2
  local stored provided
  stored="$(stored_secret "$name")"
  provided="${!name:-}"
  if [[ -n "$stored" ]]; then
    if [[ -n "$provided" && "$provided" != "$stored" ]]; then
      [[ "$mode" == pinned ]] && die "GitHub secret $name differs from the value this server already uses (in $SECRETS_FILE). Changing it would break existing data. Remove the GitHub secret (the stored value will keep being used) or set it back to the original."
      printf '%s' "$provided"; return
    fi
    printf '%s' "$stored"
  elif [[ -n "$provided" ]]; then
    printf '%s' "$provided"
  else
    log "Generating $name on the server (first deploy)." >&2
    "$@"
  fi
}

KMS_MASTER_KEY="$(resolve KMS_MASTER_KEY pinned gen_fernet)"
POSTGRES_PASSWORD="$(resolve POSTGRES_PASSWORD pinned gen_hex 24)"
API_SECRET_KEY="$(resolve API_SECRET_KEY rotatable gen_hex 32)"
GENERATED_DASHBOARD_PASSWORD=0
if [[ -z "$(stored_secret DASHBOARD_PASSWORD)" && -z "${DASHBOARD_PASSWORD:-}" ]]; then
  GENERATED_DASHBOARD_PASSWORD=1
fi
DASHBOARD_PASSWORD="$(resolve DASHBOARD_PASSWORD rotatable gen_password)"
DASHBOARD_USER="${DASHBOARD_USER:-sentinel}"

[[ "$KMS_MASTER_KEY" =~ ^[A-Za-z0-9_-]{43}=$ ]] \
  || die "KMS_MASTER_KEY is not a valid Fernet key (python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\")"
# Goes into a postgres:// URL unescaped, so keep it URL-safe.
[[ "$POSTGRES_PASSWORD" =~ ^[A-Za-z0-9_-]+$ ]] \
  || die "POSTGRES_PASSWORD may only contain letters, digits, '-' and '_'"
[[ -n "$API_SECRET_KEY" ]] || die "API_SECRET_KEY resolved empty"
(( ${#DASHBOARD_PASSWORD} >= 12 )) || die "DASHBOARD_PASSWORD must be at least 12 characters"
[[ "$DASHBOARD_PASSWORD" =~ ^[[:print:]]+$ ]] \
  || die "DASHBOARD_PASSWORD must be printable characters on a single line"
[[ "$DASHBOARD_PASSWORD" != *'"'* && "$DASHBOARD_PASSWORD" != *'\'* ]] \
  || die "DASHBOARD_PASSWORD may not contain double quotes or backslashes"
[[ "$DASHBOARD_USER" =~ ^[A-Za-z0-9._-]{1,64}$ ]] \
  || die "DASHBOARD_USER may only contain letters, digits, '.', '_' and '-'"

FIRST_SECRETS=0; [[ -f "$SECRETS_FILE" ]] || FIRST_SECRETS=1
cat > "$SECRETS_FILE" <<EOF
KMS_MASTER_KEY=${KMS_MASTER_KEY}
POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
API_SECRET_KEY=${API_SECRET_KEY}
DASHBOARD_PASSWORD=${DASHBOARD_PASSWORD}
EOF
chmod 600 "$SECRETS_FILE"
if (( FIRST_SECRETS )); then
  echo "NOTICE: created $SECRETS_FILE. Back it up off the server (scp root@<host>:$SECRETS_FILE .) — without it, stored persona credentials cannot be decrypted." >&2
fi

# --- 2. Write .env (rebuilt every deploy from the resolved values) -----------
cat > "$APP_DIR/.env" <<EOF
ENVIRONMENT=production
POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
KMS_MASTER_KEY=${KMS_MASTER_KEY}
API_SECRET_KEY=${API_SECRET_KEY}
ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY:-}
CORS_ALLOW_ORIGINS=https://${SITE_DOMAIN}
EOF
chmod 600 "$APP_DIR/.env"
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

# The workers have no healthcheck, so --wait counts them as healthy the moment
# they start — even if they then crash-loop. Watch them for a bit and fail
# loudly, with their logs, instead of reporting a green deploy with a dead worker.
sleep 20
for svc in worker worker-logins; do
  cid="$("${COMPOSE[@]}" ps -q "$svc")"
  [[ -n "$cid" ]] || die "$svc container is missing."
  if [[ "$(docker inspect -f '{{.State.Running}} {{.RestartCount}}' "$cid")" != "true 0" ]]; then
    docker logs --tail 40 "$cid" >&2 || true
    die "$svc is not staying up (state: $(docker inspect -f '{{.State.Status}}, restarts={{.RestartCount}}' "$cid")). Logs above."
  fi
done

# --- 6. Shared Caddy proxy (/opt/edge) -------------------------------------------
log "Updating shared reverse proxy in $EDGE_DIR..."
mkdir -p "$EDGE_DIR/conf"
cp "$APP_DIR/edge/docker-compose.yml" "$EDGE_DIR/docker-compose.yml"
printf 'SITE_DOMAIN=%s\n' "$SITE_DOMAIN" > "$EDGE_DIR/.env"

EDGE=(docker compose -f "$EDGE_DIR/docker-compose.yml" --project-directory "$EDGE_DIR")
CADDY_IMAGE=caddy:2

# Build the new config in a staging dir and validate it with the same Caddy
# image before it goes anywhere near the running proxy. Fixed paths, wiped
# and recreated each deploy.
STAGE=/opt/sentinel/edge-stage
BACKUP=/opt/sentinel/edge-backup
rm -rf /opt/sentinel/edge-stage /opt/sentinel/edge-backup
mkdir -m 700 /opt/sentinel/edge-stage /opt/sentinel/edge-backup
cp "$APP_DIR/edge/conf/Caddyfile" "$STAGE/Caddyfile"

# bcrypt hash of the dashboard password, made by Caddy itself. The password
# goes in on stdin, never on a command line.
DASHBOARD_HASH="$(printf '%s\n' "$DASHBOARD_PASSWORD" \
  | docker run --rm -i "$CADDY_IMAGE" caddy hash-password 2>/dev/null | tail -n1 | tr -d '\r')"
[[ "$DASHBOARD_HASH" =~ ^\$2[aby]\$[0-9]{2}\$[./A-Za-z0-9]{53}$ ]] \
  || die "Could not hash the dashboard password with $CADDY_IMAGE (got: '${DASHBOARD_HASH:0:7}...')."
cat > "$STAGE/sentinel-access.caddy" <<EOF
# Written by /opt/sentinel/remote-deploy.sh — do not edit; set the
# DASHBOARD_PASSWORD / DASHBOARD_USER GitHub secrets and redeploy instead.
@sentinel_protected path /security /security/*
basic_auth @sentinel_protected {
	${DASHBOARD_USER} ${DASHBOARD_HASH}
}
EOF

if ! docker run --rm -e SITE_DOMAIN="$SITE_DOMAIN" -v "$STAGE:/etc/caddy:ro" "$CADDY_IMAGE" \
     caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile >"$STAGE/validate.log" 2>&1; then
  tail -n 20 "$STAGE/validate.log" >&2
  die "The new Caddy config is invalid (output above); the running proxy was left untouched."
fi

cp -a "$EDGE_DIR/conf/." "$BACKUP/" 2>/dev/null || true
install -m 644 "$STAGE/Caddyfile" "$EDGE_DIR/conf/Caddyfile"
install -m 600 "$STAGE/sentinel-access.caddy" "$EDGE_DIR/conf/sentinel-access.caddy"

reload_caddy() {
  "${EDGE[@]}" exec -T caddy caddy reload --config /etc/caddy/Caddyfile --adapter caddyfile
}

if [[ -z "$("${EDGE[@]}" ps -q caddy 2>/dev/null)" ]]; then
  # First start: make sure nothing else holds the ports Caddy binds (443, and
  # its internal plain-HTTP port 8089 — see the Caddyfile; port 80 belongs to
  # another app on this box and is deliberately not used), otherwise Caddy
  # would crash-loop silently.
  for port in 443 8089; do
    if ss -ltnH "sport = :$port" | grep -q .; then
      die "Port $port is already in use on this server ($(ss -ltnpH "sport = :$port" | head -1)). Free it, then redeploy."
    fi
  done
  "${EDGE[@]}" up -d
else
  "${EDGE[@]}" up -d
  # Picks up Caddyfile changes without dropping connections. If the running
  # Caddy rejects it anyway, put the previous files back.
  if ! reload_caddy; then
    echo "WARNING: Caddy rejected the new config; restoring the previous one." >&2
    cp -a "$BACKUP/." "$EDGE_DIR/conf/"
    reload_caddy || "${EDGE[@]}" restart caddy
    die "Caddy reload failed; the previous proxy config was restored."
  fi
fi
rm -rf /opt/sentinel/edge-stage /opt/sentinel/edge-backup

# --- 7. Smoke checks ----------------------------------------------------------------
log "Smoke checks..."
curl -fsS --retry 10 --retry-delay 3 --retry-all-errors http://127.0.0.1:8100/healthz >/dev/null \
  || die "API not healthy on 127.0.0.1:8100"
curl -fsS --retry 10 --retry-delay 3 --retry-all-errors -o /dev/null http://127.0.0.1:3100/security \
  || die "Web not healthy on 127.0.0.1:3100"
# Through Caddy. TLS may still be provisioning on the very first deploy, so
# "unreachable" is a warning, not a failure — but reachable WITHOUT a password
# is a hard failure.
anon_code="$(curl -s -o /dev/null -w '%{http_code}' --retry 10 --retry-delay 3 \
  "https://${SITE_DOMAIN}/security" || true)"
if [[ "$anon_code" == "401" ]]; then
  log "Dashboard asks for a password (401 without credentials)."
elif [[ "$anon_code" =~ ^[23] ]]; then
  die "https://${SITE_DOMAIN}/security answered $anon_code WITHOUT a password: the lock-down is not active."
else
  echo "WARNING: https://${SITE_DOMAIN}/security not reachable yet (HTTP $anon_code; first-time certificate issuance can take a minute; check: docker logs edge-caddy-1)." >&2
fi
# Credentials go to curl on stdin (-K -), not on its command line.
if printf 'user = "%s:%s"\n' "$DASHBOARD_USER" "$DASHBOARD_PASSWORD" \
     | curl -K - -fsS --retry 10 --retry-delay 3 --retry-all-errors -o /dev/null \
       "https://${SITE_DOMAIN}/security/api/healthz"; then
  log "Live: https://${SITE_DOMAIN}/security (user: ${DASHBOARD_USER})"
else
  echo "WARNING: https://${SITE_DOMAIN}/security/api/healthz not reachable with the dashboard password yet." >&2
fi
if (( GENERATED_DASHBOARD_PASSWORD )); then
  echo "NOTICE: generated a dashboard password. Read it on the server with: grep DASHBOARD_PASSWORD $SECRETS_FILE  (or set the DASHBOARD_PASSWORD GitHub secret to choose your own, then redeploy)." >&2
fi

docker image prune -f >/dev/null
log "Done."
