# Production deploy — Hetzner (shared with the accounting app)

Sentinel runs on the same Hetzner server as Accsys Accounting, on the same
domain, under a path:

| URL | What |
|---|---|
| `https://accsysn.duckdns.org/security` | Sentinel dashboard (Next.js) |
| `https://accsysn.duckdns.org/security/api/docs` | Sentinel API (FastAPI / Swagger) |
| `http://accsysn.duckdns.org:8000/` | Accsys accounting, **unchanged** |
| `http://accsysn.duckdns.org/` (port 80) | another app on the box (`mep-web`), **unchanged**, not ours |

Use the `https://` links. Plain `http://accsysn.duckdns.org/security` lands
on port 80, which belongs to `mep-web`, so it shows that app's 404 instead.

## How it fits together

```
Internet
  ├─ :443 ──► Caddy  (/opt/edge, host network, Let's Encrypt via TLS-ALPN on 443)
  │             ├─ /security/api/*  ─► 127.0.0.1:8100  sentinel api   (prefix stripped)
  │             ├─ /security[/*]    ─► 127.0.0.1:3100  sentinel web   (prefix kept, Next basePath)
  │             └─ /*               ─► 302 redirect to http://<domain>/... (port 80's owner)
  ├─ :80 ───► mep-web     (another app, not touched by this repo)
  └─ :8000 ─► accsys app  (direct, as before)

/opt/accsys     accounting compose project (untouched by this repo)
/opt/sentinel   api, worker, web, postgres, redis   (this repo)
/opt/edge       shared Caddy proxy                  (deployed by this repo)
```

The dashboard calls the API at the relative URL `/security/api` (same origin),
so there's no CORS hop in production.

## Deploy flow

Deploying is the `deploy` job in `.github/workflows/ci.yml`. It runs
automatically on every push to `main`, **after both `lint-and-test` and
`container-build` pass**, and never for pull requests. To deploy by hand, go to
**Actions → CI → Run workflow** and pick `main`; that runs the tests first, then
deploys.

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

GitHub secrets are write-only, so they can't be copied over from the
accounting repo. Only these three are needed, and they're the same values the
accounting repo uses:

| Secret | Value |
|---|---|
| `HETZNER_HOST` | `accsysn.duckdns.org` (a domain works; the workflow resolves it) or the server IP |
| `HETZNER_USER` | `root` (what `server-setup.sh` in the accounting repo set up) |
| `HETZNER_SSH_KEY` | the same private key you pasted into the accounting repo (the whole file, including the `-----BEGIN … KEY-----` lines) |

The app's own secrets are **generated on the server on the first deploy** and
kept in `/opt/sentinel/.secrets` (mode 600): `KMS_MASTER_KEY`,
`POSTGRES_PASSWORD`, `API_SECRET_KEY`. **Back that file up once** after the
first deploy:

```bash
scp root@accsysn.duckdns.org:/opt/sentinel/.secrets ./sentinel-secrets.backup
```

Optional secrets: `ANTHROPIC_API_KEY` (LLM-assisted phases), and
`KMS_MASTER_KEY` / `POSTGRES_PASSWORD` / `API_SECRET_KEY` only if you want to
supply your own values instead of the generated ones.

Optional repository **variable** `SITE_DOMAIN` (defaults to `accsysn.duckdns.org`).

### Server

Nothing to install by hand: Docker is already there from the accounting setup,
and `server-setup.sh` there already opened port 443 in `ufw`. If the
Hetzner Cloud firewall (in the Hetzner console) is in use, allow 443 there too.

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
- **`KMS_MASTER_KEY` and `POSTGRES_PASSWORD` must never change.** Every stored
  persona credential is encrypted under the KMS key, and Postgres only accepts
  the password it was created with. Once they're in `/opt/sentinel/.secrets`,
  a deploy that's given a *different* value through a GitHub secret aborts
  rather than breaking data. `API_SECRET_KEY` may be rotated by setting the secret.
- **Lost `.secrets` file.** If it's missing while the `sentinel_pgdata` volume
  still exists, the deploy aborts instead of generating new values that can't
  open the existing database. Restore the backup to `/opt/sentinel/.secrets`.
- **Port 80 belongs to another app.** `mep-web` publishes port 80 on this box,
  so Caddy never binds it. Its plain-HTTP listener is moved to 8089 (closed by
  `ufw`), it doesn't redirect http to https, and it gets certificates with the
  TLS-ALPN-01 challenge, which needs only port 443. On the first proxy start
  the script checks that 443 and 8089 are free, and if they aren't it fails
  naming the process instead of letting Caddy crash-loop.
- **First-time HTTPS.** Caddy needs port 443 reachable from the internet to get
  the certificate, and the first issuance can take a minute. The script only
  warns if the HTTPS check fails then. Logs: `docker logs edge-caddy-1`.
  Certificates live in the `edge_caddy_data` volume; don't delete it, or you
  may hit Let's Encrypt rate limits.
- **Worker crash-loops.** The worker has no healthcheck, so `compose --wait`
  would report it healthy even while it restart-loops. The deploy watches it
  for 20 s after start and fails with its last 40 log lines if it isn't still
  up with zero restarts.
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
