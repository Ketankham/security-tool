#!/usr/bin/env bash
# Runs ON the Hetzner server, from /opt/sentinel, invoked by
# the `deploy` job in .github/workflows/ci.yml after it has copied over:
#   sentinel-images.tar.gz  docker-compose.prod.yml  remote-deploy.sh
#   manage-users.sh  edge/
#
# Needs /opt/sentinel/dashboard-users (the per-person dashboard logins, created
# with manage-users.sh). Without a valid one the deploy stops in step 0, before
# anything is loaded or restarted, and says how to create it.
#
# Optional env (GitHub secrets — all may be left unset):
#   KMS_MASTER_KEY  API_SECRET_KEY  POSTGRES_PASSWORD  SENTINEL_PROXY_SECRET
#       Generated on the server on first deploy and kept in
#       /opt/sentinel/.secrets from then on. Set them only to supply your own
#       values; a supplied KMS key / DB password that differs from the stored
#       one aborts the deploy instead of silently breaking data.
#       (SENTINEL_PROXY_SECRET is the shared secret Caddy sends the API so it can
#       trust the signed-in username; CI does not pass it, the server generates it.)
#   ANTHROPIC_API_KEY  SITE_DOMAIN (default accsysn.duckdns.org)
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

# --- 0. Dashboard logins must exist (fail closed, before anything changes) ---
# Everything under /security is behind per-person logins, and the API refuses
# requests that did not come through that login. A deploy without logins would
# lock everybody out, so check first: nothing is loaded or restarted until the
# users file is valid, and the site keeps running the previous release.
USERS_FILE=/opt/sentinel/dashboard-users
MANAGE_USERS="$APP_DIR/manage-users.sh"

die_no_logins() {
  cat >&2 <<MSG

$1

This release puts every page under /security behind per-person logins, and
there is no valid login yet, so deploying it would lock everybody out.
NOTHING was loaded or restarted: the site is still running the previous
release. Create the logins on the server:

  scp infra/deploy/manage-users.sh root@${SITE_DOMAIN}:/opt/sentinel/    # from your checkout; only if the script is not on the server yet
  ssh root@${SITE_DOMAIN}
  bash /opt/sentinel/manage-users.sh add ketan        # prompts for a password (12+ characters)
  bash /opt/sentinel/manage-users.sh add <tester>     # one login per person
  bash /opt/sentinel/manage-users.sh list

Then redeploy: GitHub -> Actions -> CI -> Run workflow (main).
MSG
  die "no valid dashboard logins (see above)."
}

[[ -f "$MANAGE_USERS" ]] \
  || die "$MANAGE_USERS is missing: the deploy bundle did not include infra/deploy/manage-users.sh (check the 'Bundle images and deploy files' step in .github/workflows/ci.yml)."
[[ -f "$USERS_FILE" ]] || die_no_logins "$USERS_FILE does not exist."
if ! users_problem="$(USERS_FILE="$USERS_FILE" bash "$MANAGE_USERS" render /dev/null 2>&1)"; then
  die_no_logins "$users_problem"
fi
log "Dashboard logins: $(USERS_FILE="$USERS_FILE" bash "$MANAGE_USERS" list | paste -sd, -)"

# --- 1. Resolve app secrets (stored on server > GitHub secret > generate) -----
umask 077

stored_secret() { grep -m1 "^$1=" "$SECRETS_FILE" 2>/dev/null | cut -d= -f2- || true; }
# Fernet key: urlsafe-base64 of 32 random bytes (44 chars ending in '=').
gen_fernet() { head -c 32 /dev/urandom | base64 | tr '+/' '-_' | tr -d '\n'; }
gen_hex() { head -c "$1" /dev/urandom | od -An -vtx1 | tr -d ' \n'; }

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
# Shared by Caddy (/opt/edge/.env) and the API (/opt/sentinel/.env): the API only
# believes the signed-in username when the request carries this secret.
NEW_PROXY_SECRET=0; [[ -n "$(stored_secret SENTINEL_PROXY_SECRET)" ]] || NEW_PROXY_SECRET=1
SENTINEL_PROXY_SECRET="$(resolve SENTINEL_PROXY_SECRET rotatable gen_hex 32)"

[[ "$KMS_MASTER_KEY" =~ ^[A-Za-z0-9_-]{43}=$ ]] \
  || die "KMS_MASTER_KEY is not a valid Fernet key (python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\")"
# Goes into a postgres:// URL unescaped, so keep it URL-safe.
[[ "$POSTGRES_PASSWORD" =~ ^[A-Za-z0-9_-]+$ ]] \
  || die "POSTGRES_PASSWORD may only contain letters, digits, '-' and '_'"
[[ -n "$API_SECRET_KEY" ]] || die "API_SECRET_KEY resolved empty"
# Unquoted in two env files and a Caddy placeholder: keep it plain.
[[ "$SENTINEL_PROXY_SECRET" =~ ^[A-Za-z0-9_-]{32,128}$ ]] \
  || die "SENTINEL_PROXY_SECRET must be 32-128 characters of letters, digits, '-' and '_'"

FIRST_SECRETS=0; [[ -f "$SECRETS_FILE" ]] || FIRST_SECRETS=1
cat > "$SECRETS_FILE" <<EOF
KMS_MASTER_KEY=${KMS_MASTER_KEY}
POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
API_SECRET_KEY=${API_SECRET_KEY}
SENTINEL_PROXY_SECRET=${SENTINEL_PROXY_SECRET}
EOF
chmod 600 "$SECRETS_FILE"
if (( FIRST_SECRETS )); then
  echo "NOTICE: created $SECRETS_FILE. Back it up off the server (scp root@<host>:$SECRETS_FILE .) — without it, stored persona credentials cannot be decrypted." >&2
elif (( NEW_PROXY_SECRET )); then
  echo "NOTICE: $SECRETS_FILE now also holds SENTINEL_PROXY_SECRET. Copy the file off the server again (scp root@<host>:$SECRETS_FILE .)." >&2
fi

# --- 2. Write .env (rebuilt every deploy from the resolved values) -----------
cat > "$APP_DIR/.env" <<EOF
ENVIRONMENT=production
POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
KMS_MASTER_KEY=${KMS_MASTER_KEY}
API_SECRET_KEY=${API_SECRET_KEY}
ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY:-}
CORS_ALLOW_ORIGINS=https://${SITE_DOMAIN}
SENTINEL_PROXY_SECRET=${SENTINEL_PROXY_SECRET}
REQUIRE_IDENTITY=true
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
# Holds the proxy secret, so mode 600 from the first byte (written aside, then renamed).
( umask 077; printf 'SITE_DOMAIN=%s\nSENTINEL_PROXY_SECRET=%s\n' "$SITE_DOMAIN" "$SENTINEL_PROXY_SECRET" > "$EDGE_DIR/.env.new" )
chmod 600 "$EDGE_DIR/.env.new"
mv -f "$EDGE_DIR/.env.new" "$EDGE_DIR/.env"

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
# Logins -> Caddy snippet. This re-validates the users file and refuses an empty
# one (an empty basic_auth block passes `caddy validate` and would let nobody in).
USERS_FILE="$USERS_FILE" bash "$MANAGE_USERS" render "$STAGE/sentinel-access.caddy" \
  || die "Could not render the dashboard logins from $USERS_FILE; the running proxy was left untouched."

if ! docker run --rm --env-file "$EDGE_DIR/.env" -v "$STAGE:/etc/caddy:ro" "$CADDY_IMAGE" \
     caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile >"$STAGE/validate.log" 2>&1; then
  tail -n 20 "$STAGE/validate.log" >&2
  die "The new Caddy config is invalid (output above); the running proxy was left untouched."
fi

cp -a "$EDGE_DIR/conf/." "$BACKUP/" 2>/dev/null || true
# The logins first, then the Caddyfile that imports them (never the other way round).
install -m 600 "$STAGE/sentinel-access.caddy" "$EDGE_DIR/conf/sentinel-access.caddy.new"
mv -f "$EDGE_DIR/conf/sentinel-access.caddy.new" "$EDGE_DIR/conf/sentinel-access.caddy"
install -m 644 "$STAGE/Caddyfile" "$EDGE_DIR/conf/Caddyfile"

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
    if ! grep -qs 'sentinel-access.caddy' "$EDGE_DIR/conf/Caddyfile"; then
      # The previous config predates the logins, i.e. it has no lock. Do not
      # put an unlocked proxy back in front of the new (identity-requiring) API.
      "${EDGE[@]}" stop caddy >/dev/null 2>&1 || true
      die "Caddy rejected the new config and the previous one has no login. The proxy was STOPPED so the site stays closed. Read the Caddy error with: docker logs edge-caddy-1, fix it, and redeploy."
    fi
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

# (1) The lock is on: an anonymous visitor must get 401. TLS may still be
# provisioning on the very first deploy, so "unreachable" is only a warning;
# reachable WITHOUT a login is a hard failure, and the proxy is stopped so the
# site is closed rather than open.
anon_code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 20 --retry 10 --retry-delay 3 --retry-all-errors \
  "https://${SITE_DOMAIN}/security" || true)"
case "$anon_code" in
  401) log "Dashboard asks for a login (401 without credentials)." ;;
  2??|3??)
    "${EDGE[@]}" stop caddy >/dev/null 2>&1 || true
    die "https://${SITE_DOMAIN}/security answered $anon_code WITHOUT a login: the lock-down is not active. The proxy was STOPPED so the site stays closed; check $EDGE_DIR/conf (Caddyfile + sentinel-access.caddy), then redeploy." ;;
  *) echo "WARNING: https://${SITE_DOMAIN}/security not checked (HTTP $anon_code; first-time certificate issuance can take a minute; check: docker logs edge-caddy-1)." >&2 ;;
esac

# (2) The API must not believe an identity header that did not come through
# Caddy. Straight to the API, with only a spoofed user header: 401.
spoof_code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 -H 'X-Sentinel-User: smoke' \
  http://127.0.0.1:8100/whoami || true)"
[[ "$spoof_code" == 401 ]] \
  || die "API on 127.0.0.1:8100 answered $spoof_code (not 401) to /whoami with a spoofed X-Sentinel-User and no proxy secret: it trusts unverified identity headers (check REQUIRE_IDENTITY / SENTINEL_PROXY_SECRET in $APP_DIR/.env)."

# (3) ...but it must accept the identity Caddy sends. The secret goes to curl on
# stdin (-K -), never on a command line.
whoami_body="$(umask 077; mktemp)"
trap 'rm -f "$whoami_body"' EXIT
proxied_code="$(printf 'header = "X-Sentinel-Proxy-Secret: %s"\nheader = "X-Sentinel-User: deploy-smoke"\n' "$SENTINEL_PROXY_SECRET" \
  | curl -K - -s -o "$whoami_body" -w '%{http_code}' --max-time 10 http://127.0.0.1:8100/whoami || true)"
if [[ "$proxied_code" != 200 ]] || ! grep -Eq '"username": *"deploy-smoke"' "$whoami_body"; then
  die "API on 127.0.0.1:8100 did not accept the proxy identity on /whoami (HTTP $proxied_code, expected 200 with username deploy-smoke). The API and Caddy probably disagree about SENTINEL_PROXY_SECRET ($APP_DIR/.env vs $EDGE_DIR/.env)."
fi
rm -f "$whoami_body"
log "API accepts the proxy identity and refuses a spoofed one."

# (4) Through Caddy, the one open path: liveness. Warning only.
if curl -fsS --retry 10 --retry-delay 3 --retry-all-errors -o /dev/null \
     "https://${SITE_DOMAIN}/security/api/healthz"; then
  log "Live: https://${SITE_DOMAIN}/security (sign-in required)"
else
  echo "WARNING: https://${SITE_DOMAIN}/security/api/healthz not reachable yet (first-time certificate issuance can take a minute; check: docker logs edge-caddy-1)." >&2
fi

docker image prune -f >/dev/null
log "Done."
