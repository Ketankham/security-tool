# Production deploy — Hetzner (shared with the accounting app)

Sentinel runs on the same Hetzner server as Accsys Accounting, on the same
domain, under a path:

| URL | What |
|---|---|
| `https://accsysn.duckdns.org/security` | Sentinel dashboard (Next.js) |
| `https://accsysn.duckdns.org/security/api/docs` | Sentinel API (FastAPI / Swagger) |
| `https://accsysn.duckdns.org/` | Accsys accounting (new HTTPS entry, same app) |
| `http://accsysn.duckdns.org:8000/` | Accsys accounting — **unchanged**, still works |

## How it fits together

```
Internet
  ├─ :80/:443 ──► Caddy  (/opt/edge, host network, auto Let's Encrypt)
  │                 ├─ /security/api/*  ─► 127.0.0.1:8100  sentinel api   (prefix stripped)
  │                 ├─ /security[/*]    ─► 127.0.0.1:3100  sentinel web   (prefix kept, Next basePath)
  │                 └─ /*               ─► 127.0.0.1:8000  accsys app
  └─ :8000 ───────────────────────────────►               accsys app     (direct, as before)

/opt/accsys     accounting compose project (untouched by this repo)
/opt/sentinel   api, worker, web, postgres, redis   (this repo)
/opt/edge       shared Caddy proxy                  (deployed by this repo)
```

The dashboard calls the API at the relative URL `/security/api` (same origin),
so there's no CORS hop in production.

## Deploy flow

`.github/workflows/deploy.yml` runs automatically **after CI succeeds on a push
to `main`** (pull-request CI runs never deploy). It can also be run by hand from
the Actions tab (`workflow_dispatch`).

1. Builds `sentinel-api`, `sentinel-worker` (with Chromium) and `sentinel-web`
   (built with `NEXT_PUBLIC_BASE_PATH=/security`, `NEXT_PUBLIC_API_BASE=/security/api`).
2. `docker save`s them into one tarball and copies it, plus `infra/deploy/*`,
   to `/opt/sentinel`.
3. Runs `remote-deploy.sh` on the server, which:
   - validates the secrets and refuses to start with a changed `KMS_MASTER_KEY` (see below),
   - writes `/opt/sentinel/.env` from the secrets,
   - loads the images, starts postgres + redis, runs `alembic upgrade head`,
   - starts api / worker / web and waits for their health checks,
   - installs or reloads the shared Caddy proxy in `/opt/edge`,
   - smoke-checks `/healthz` locally and through `https://<domain>/security/api/healthz`.

## One-time setup

### GitHub secrets (security-tool repo → Settings → Secrets and variables → Actions)

| Secret | Value |
|---|---|
| `HETZNER_HOST` | same as the accounting repo |
| `HETZNER_USER` | same as the accounting repo |
| `HETZNER_SSH_KEY` | same as the accounting repo |
| `KMS_MASTER_KEY` | `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"` — **back this up** |
| `API_SECRET_KEY` | `openssl rand -hex 32` |
| `POSTGRES_PASSWORD` | `openssl rand -hex 24` (letters/digits/`-`/`_` only — it goes into a DB URL) |
| `ANTHROPIC_API_KEY` | optional; needed only for the LLM-assisted phases |

Optional repository **variable** `SITE_DOMAIN` (defaults to `accsysn.duckdns.org`).

### Server

Nothing to install by hand: Docker is already there from the accounting setup,
and `server-setup.sh` there already opened ports 80/443 in `ufw`. If the
Hetzner Cloud firewall (in the Hetzner console) is in use, allow 80 and 443 there too.

## Edge cases and guard rails

- **The accounting deploy stops containers on port 8000.** It runs
  `docker ps --filter publish=8000 | xargs docker stop`, and that filter matches
  the *container-side* port. So Sentinel never uses 8000 anywhere: the API
  listens on 8100 inside and outside its container, and Caddy publishes no
  Docker ports at all (host networking).
- **Each deploy only touches its own folder.** Separate compose projects
  (`accsys`, `sentinel`, `edge`) mean `down` / `--remove-orphans` in one never
  removes another's containers. While the accounting app redeploys,
  `https://<domain>/` briefly returns 502; `/security` is unaffected.
- **`KMS_MASTER_KEY` must never change.** Every stored persona credential is
  encrypted under it. The first deploy pins its SHA-256 fingerprint in
  `/opt/sentinel/.kms_fingerprint`, and later deploys abort if the secret
  differs. To rotate on purpose (losing stored credentials), delete that file
  on the server and redeploy.
- **`POSTGRES_PASSWORD` only takes effect on the first start.** Postgres sets
  it when it creates the `pgdata` volume. Changing the secret later breaks DB
  auth: change the password inside Postgres first (`ALTER USER sentinel PASSWORD ...`),
  then update the secret.
- **Ports 80/443 already in use.** On the first proxy start the script checks
  for this and fails with the process name instead of letting Caddy crash-loop.
- **First-time HTTPS.** Caddy needs port 80 reachable from the internet to get
  the certificate, and the first issuance can take a minute. The script only
  warns if the HTTPS check fails then. Logs: `docker logs edge-caddy-1`.
  Certificates live in the `edge_caddy_data` volume; don't delete it, or you
  may hit Let's Encrypt rate limits.
- **Memory.** The worker runs one scan at a time (`--concurrency=1`), is capped
  at 2 GB, and has a 512 MB `/dev/shm` (Chromium crashes on Docker's 64 MB default).
- **Recon binaries.** `subfinder` / `httpx` / `tlsx` aren't in the worker image;
  recon uses its documented degrade path without them.

## Public exposure: read before relying on it

The API still uses the **dev auth stand-in** (`X-Org-Id` header,
`apps/api/sentinel_api_app/deps.py`), and `POST /organizations` is open. Right
now anyone who finds the URL can create an org and use the UI. Ownership
verification still stops them scanning domains they don't control. Before real
customer data goes in:

- wire Clerk (or put basic auth in the Caddyfile for `/security*`),
- add private and link-local IP blocking to the scope guard, so the worker can't
  be pointed at the server's own internal services,
- keep in mind that Hetzner acts quickly on scanning abuse reports: only scan
  targets that passed ownership verification.

## Useful commands on the server

```bash
cd /opt/sentinel && docker compose -f docker-compose.prod.yml ps
docker compose -f /opt/sentinel/docker-compose.prod.yml logs -f api worker web
docker logs -f edge-caddy-1
docker compose -f /opt/sentinel/docker-compose.prod.yml exec postgres psql -U sentinel
```
