#!/usr/bin/env bash
# Per-person dashboard logins for https://<domain>/security (Caddy basic auth).
# Runs ON the Hetzner server, as root.
#
#   manage-users.sh add <user>        create the login, or change its password
#   manage-users.sh remove <user>     delete a login (never the last one)
#   manage-users.sh list              usernames only
#   manage-users.sh render <outfile>  validate the users file and write the Caddy
#                                     snippet (this is what `apply` and the deploy use)
#   manage-users.sh apply             render, `caddy validate`, install into
#                                     /opt/edge/conf and reload Caddy
#
# `add` and `remove` only edit the users file. They take effect on the next
# deploy, or at once with `apply`.
#
# Users file (/opt/sentinel/dashboard-users, mode 600), one login per line:
#     username<space>bcrypt-hash
# usernames: lower-case letters, digits, '.', '_', '-' (1-32 chars, must start
# with a letter or digit). Passwords are never stored, only their bcrypt hash.
#
# Overridable for testing (defaults are the production paths):
#   USERS_FILE      /opt/sentinel/dashboard-users
#   EDGE_DIR        /opt/edge
#   EDGE_CONF_DIR   $EDGE_DIR/conf          (Caddyfile + sentinel-access.caddy)
#   EDGE_ENV_FILE   $EDGE_DIR/.env          (SITE_DOMAIN, SENTINEL_PROXY_SECRET)
#   CADDY_BIN       hashing/validating uses this caddy binary; if unset, a
#                   `caddy` on PATH; if there is none, docker run caddy:2
#   CADDY_IMAGE     caddy:2
#   MANAGE_USERS_RELOAD_CMD   command run by `apply` instead of the docker compose reload
#   MANAGE_USERS_ALLOW_NON_ROOT=1   skip the root check (tests only)
set -euo pipefail

USERS_FILE="${USERS_FILE:-/opt/sentinel/dashboard-users}"
EDGE_DIR="${EDGE_DIR:-/opt/edge}"
EDGE_CONF_DIR="${EDGE_CONF_DIR:-$EDGE_DIR/conf}"
EDGE_ENV_FILE="${EDGE_ENV_FILE:-$EDGE_DIR/.env}"
CADDY_IMAGE="${CADDY_IMAGE:-caddy:2}"
ACCESS_NAME=sentinel-access.caddy
IMPORT_LINE="import /etc/caddy/$ACCESS_NAME"

USER_RE='^[a-z0-9][a-z0-9._-]{0,31}$'
# shellcheck disable=SC2016  # '$' here is a regex anchor/literal, not a variable
HASH_RE='^\$2[aby]\$[0-9]{2}\$[./A-Za-z0-9]{53}$'
# Used by the deploy's own smoke check; a real login must not borrow that name.
RESERVED_USERS=(deploy-smoke)

log() { echo "==> $*" >&2; }
die() { echo "ERROR: $*" >&2; exit 1; }

usage() {
  cat >&2 <<'EOF'
usage: manage-users.sh add <user> | remove <user> | list | render <outfile> | apply
EOF
  exit 2
}

if [[ "${MANAGE_USERS_ALLOW_NON_ROOT:-}" != 1 && "$(id -u)" != 0 ]]; then
  die "run as root (sudo bash $0 ...): the users file holds password hashes."
fi

# --- users file -------------------------------------------------------------
# Prints "user hash" for every valid line (and dies if there is none, unless
# ALLOW_EMPTY=1: `add` may start from an empty file). Dies on any malformed line, naming
# the line NUMBER only (a malformed line may be a password pasted by mistake,
# so its content is never echoed). Blank lines are ignored.
read_users() {
  [[ -f "$USERS_FILE" ]] || die "$USERS_FILE does not exist. Create the first login with: bash $0 add <user>"
  local n=0 user hash extra line seen=" "
  while IFS= read -r line || [[ -n "$line" ]]; do
    n=$((n + 1))
    [[ -z "${line//[[:space:]]/}" ]] && continue
    read -r user hash extra <<<"$line"
    if [[ ! "$line" =~ ^[^[:space:]]+\ [^[:space:]]+$ || -n "$extra" ]]; then
      die "$USERS_FILE line $n is not 'username<space>bcrypt-hash' (content not shown)."
    fi
    [[ "$user" =~ $USER_RE ]] || die "$USERS_FILE line $n: invalid username (lower-case letters, digits, '.', '_', '-'; 1-32 chars)."
    [[ "$hash" =~ $HASH_RE ]] || die "$USERS_FILE line $n: the password hash for '$user' is not a valid bcrypt hash."
    [[ "$seen" != *" $user "* ]] || die "$USERS_FILE line $n: '$user' appears more than once."
    seen+="$user "
    printf '%s %s\n' "$user" "$hash"
  done <"$USERS_FILE"
  if [[ "$seen" == " " && "${ALLOW_EMPTY:-0}" != 1 ]]; then
    die "$USERS_FILE has no logins. Add one with: bash $0 add <user>"
  fi
}

# has_user "<read_users output>" <user>
has_user() { awk -v u="$2" '$1 == u { f = 1 } END { exit !f }' <<<"$1"; }

# Replace $USERS_FILE atomically (temp file in the same directory, mode 600).
# Reads the new content from stdin.
write_users() {
  local dir tmp
  dir="$(dirname "$USERS_FILE")"
  tmp="$(umask 077; mktemp "$dir/.dashboard-users.XXXXXX")"
  if ! cat >"$tmp"; then rm -f "$tmp"; die "could not write $tmp"; fi
  chmod 600 "$tmp"
  mv -f "$tmp" "$USERS_FILE"
}

# Serialise add/remove (two admins at once would lose an update).
lock_users() {
  if command -v flock >/dev/null 2>&1; then
    exec 9>"$USERS_FILE.lock"
    flock -w 30 9 || die "another manage-users.sh is running (lock: $USERS_FILE.lock)."
  fi
}

# --- hashing / caddy ----------------------------------------------------------
caddy_local() {
  if [[ -n "${CADDY_BIN:-}" ]]; then
    [[ -x "$CADDY_BIN" ]] || die "CADDY_BIN=$CADDY_BIN is not executable."
    printf '%s' "$CADDY_BIN"
  elif command -v caddy >/dev/null 2>&1; then
    command -v caddy
  fi
}

# bcrypt hash of $1, made by Caddy itself. The password goes in on stdin, never
# on a command line.
hash_password() {
  local bin out hash
  bin="$(caddy_local)"
  if [[ -n "$bin" ]]; then
    out="$(printf '%s\n' "$1" | "$bin" hash-password 2>/dev/null)" || out=""
  else
    command -v docker >/dev/null 2>&1 || die "neither a local caddy binary nor docker was found."
    out="$(printf '%s\n' "$1" | docker run --rm -i "$CADDY_IMAGE" caddy hash-password 2>/dev/null)" || out=""
  fi
  hash="$(printf '%s\n' "$out" | tail -n1 | tr -d '\r')"
  [[ "$hash" =~ $HASH_RE ]] || die "could not hash the password with Caddy (got: '${hash:0:7}...')."
  printf '%s' "$hash"
}

# --- commands ---------------------------------------------------------------
check_username() {
  [[ "$1" =~ $USER_RE ]] || die "invalid username '$1': use lower-case letters, digits, '.', '_' or '-' (1-32 characters, starting with a letter or digit)."
  local r
  for r in "${RESERVED_USERS[@]}"; do
    [[ "$1" != "$r" ]] || die "'$1' is reserved for the deploy's own checks; pick another name."
  done
}

cmd_add() {
  [[ $# -eq 1 ]] || usage
  local user="$1" pw pw2 hash existing="" found=0 u h rc
  check_username "$user"
  lock_users
  if [[ -f "$USERS_FILE" ]]; then existing="$(ALLOW_EMPTY=1 read_users)"; fi

  if [[ -t 0 ]]; then printf 'Password for %s (at least 12 characters, not shown): ' "$user" >&2; fi
  IFS= read -rs pw || die "no password given."
  if [[ -t 0 ]]; then printf '\nRepeat the password: ' >&2; fi
  IFS= read -rs pw2 || die "the password was not repeated."
  if [[ -t 0 ]]; then printf '\n' >&2; fi

  [[ "$pw" == "$pw2" ]] || die "the two passwords do not match; nothing changed."
  # Printable ASCII only (no control characters, no encoding surprises between
  # browsers); bcrypt only looks at the first 72 bytes, so refuse longer ones.
  (
    LC_ALL=C
    (( ${#pw} >= 12 )) || exit 10
    (( ${#pw} <= 72 )) || exit 11
    [[ "$pw" =~ ^[[:print:]]+$ ]] || exit 12
  ) && rc=0 || rc=$?
  case "$rc" in
    0) ;;
    10) die "the password must be at least 12 characters; nothing changed." ;;
    11) die "the password may be at most 72 characters (bcrypt limit); nothing changed." ;;
    *) die "the password may only use printable ASCII characters; nothing changed." ;;
  esac

  log "Hashing (bcrypt, takes a moment)..."
  hash="$(hash_password "$pw")"
  pw=""; pw2=""

  {
    while read -r u h; do
      [[ -z "$u" ]] && continue
      if [[ "$u" == "$user" ]]; then
        printf '%s %s\n' "$user" "$hash"; found=1
      else
        printf '%s %s\n' "$u" "$h"
      fi
    done <<<"$existing"
    (( found )) || printf '%s %s\n' "$user" "$hash"
  } | write_users
  if has_user "$existing" "$user"; then
    log "Changed the password of '$user'."
  else
    log "Added '$user'."
  fi
  log "Takes effect on the next deploy, or now with: bash $0 apply"
}

cmd_remove() {
  [[ $# -eq 1 ]] || usage
  local user="$1" existing count u h
  [[ "$user" =~ $USER_RE ]] || die "invalid username '$user'."
  lock_users
  existing="$(read_users)"
  has_user "$existing" "$user" || die "no login named '$user' (see: bash $0 list)."
  count="$(grep -c . <<<"$existing")"
  (( count > 1 )) || die "refusing to remove '$user': it is the last login, and removing it would lock everyone out of the dashboard. Add another login first."
  while read -r u h; do
    [[ "$u" == "$user" ]] || printf '%s %s\n' "$u" "$h"
  done <<<"$existing" | write_users
  log "Removed '$user'. Takes effect on the next deploy, or now with: bash $0 apply"
}

cmd_list() {
  [[ $# -eq 0 ]] || usage
  local users u h
  users="$(read_users)"
  while read -r u h; do printf '%s\n' "$u"; done <<<"$users"
}

# Validate the users file (at least one valid login) and write the Caddy
# snippet. `render /dev/null` is therefore a pure validity check.
cmd_render() {
  [[ $# -eq 1 ]] || usage
  local out="$1" users u h content tmp
  users="$(read_users)"
  content="$(
    echo "# generated by infra/deploy/manage-users.sh — do not edit"
    echo "basic_auth @sentinel_protected {"
    while read -r u h; do
      printf '\t%s %s\n' "$u" "$h"
    done <<<"$users"
    echo "}"
  )"
  if [[ -e "$out" && ! -f "$out" ]]; then
    printf '%s\n' "$content" >"$out"    # /dev/null and friends: write through, don't replace
  else
    tmp="$(umask 077; mktemp "$(dirname "$out")/.sentinel-access.XXXXXX")"
    printf '%s\n' "$content" >"$tmp"
    chmod 600 "$tmp"
    mv -f "$tmp" "$out"
  fi
}

# Run `caddy validate` on the Caddyfile in $1 (with the access file next to it).
validate_caddy() {
  local stage="$1" bin k v
  [[ -f "$EDGE_ENV_FILE" ]] || die "$EDGE_ENV_FILE is missing: the proxy has not been deployed with logins yet. Deploy PR-A first (the deploy writes it)."
  # An empty secret would still validate (Caddy accepts a value-less header_up),
  # but the API would then refuse every request: catch it here.
  grep -Eq '^SENTINEL_PROXY_SECRET=.{32,}$' "$EDGE_ENV_FILE" \
    || die "$EDGE_ENV_FILE has no SENTINEL_PROXY_SECRET (32+ characters): deploy PR-A first (the deploy writes it)."
  bin="$(caddy_local)"
  if [[ -n "$bin" ]]; then
    # No docker here (tests, or a box with a caddy binary): the Caddyfile
    # imports /etc/caddy/..., so validate a copy that points at the stage dir.
    sed "s#/etc/caddy/#$stage/#g" "$stage/Caddyfile" >"$stage/Caddyfile.local"
    local rc=0
    (
      while IFS='=' read -r k v; do
        if [[ "$k" =~ ^[A-Z_][A-Z0-9_]*$ ]]; then export "$k=$v"; fi
      done <"$EDGE_ENV_FILE"
      "$bin" validate --config "$stage/Caddyfile.local" --adapter caddyfile
    ) >"$stage/validate.log" 2>&1 || rc=$?
    rm -f "$stage/Caddyfile.local"
    return $rc
  fi
  command -v docker >/dev/null 2>&1 || die "neither a local caddy binary nor docker was found."
  docker run --rm --env-file "$EDGE_ENV_FILE" -v "$stage:/etc/caddy:ro" "$CADDY_IMAGE" \
    caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile >"$stage/validate.log" 2>&1
}

reload_caddy() {
  if [[ -n "${MANAGE_USERS_RELOAD_CMD:-}" ]]; then
    bash -c "$MANAGE_USERS_RELOAD_CMD"
    return
  fi
  local edge=(docker compose -f "$EDGE_DIR/docker-compose.yml" --project-directory "$EDGE_DIR")
  if [[ -z "$("${edge[@]}" ps -q caddy 2>/dev/null)" ]]; then
    log "Caddy is not running; it will load the new logins when it starts."
    return 0
  fi
  "${edge[@]}" exec -T caddy caddy reload --config /etc/caddy/Caddyfile --adapter caddyfile
}

cmd_apply() {
  [[ $# -eq 0 ]] || usage
  local live="$EDGE_CONF_DIR/$ACCESS_NAME" stage backup="" rc
  [[ -f "$EDGE_CONF_DIR/Caddyfile" ]] || die "$EDGE_CONF_DIR/Caddyfile not found. Deploy PR-A first."
  grep -qxF "$IMPORT_LINE" <(sed 's/^[[:space:]]*//; s/[[:space:]]*$//' "$EDGE_CONF_DIR/Caddyfile") \
    || die "$EDGE_CONF_DIR/Caddyfile does not contain '$IMPORT_LINE': deploy PR-A first (the deploy installs the new Caddyfile). Nothing changed."

  stage="$(umask 077; mktemp -d "${TMPDIR:-/tmp}/sentinel-users-stage.XXXXXX")"
  # Expand $stage now on purpose: it is a local, gone when the EXIT trap fires.
  # shellcheck disable=SC2064
  trap "rm -rf '$stage'" EXIT
  cp "$EDGE_CONF_DIR/Caddyfile" "$stage/Caddyfile"
  cmd_render "$stage/$ACCESS_NAME"
  if ! validate_caddy "$stage"; then
    tail -n 20 "$stage/validate.log" >&2 || true
    die "Caddy rejected the new config (output above); the running proxy was left untouched."
  fi

  if [[ -f "$live" ]]; then
    backup="$stage/previous-$ACCESS_NAME"
    cp -p "$live" "$backup"
  fi
  install -m 600 "$stage/$ACCESS_NAME" "$live.new"
  mv -f "$live.new" "$live"
  if reload_caddy; then
    log "Applied: $(cmd_list | wc -l | tr -d ' ') login(s) active."
  else
    rc=$?
    echo "WARNING: Caddy rejected the reload; restoring the previous logins." >&2
    if [[ -n "$backup" ]]; then
      install -m 600 "$backup" "$live.new"; mv -f "$live.new" "$live"
      reload_caddy || echo "WARNING: reload of the restored config failed too; check: docker logs edge-caddy-1" >&2
    fi
    die "reload failed (exit $rc); previous logins restored."
  fi
}

[[ $# -ge 1 ]] || usage
cmd="$1"; shift
case "$cmd" in
  add) cmd_add "$@" ;;
  remove) cmd_remove "$@" ;;
  list) cmd_list "$@" ;;
  render) cmd_render "$@" ;;
  apply) cmd_apply "$@" ;;
  *) usage ;;
esac
