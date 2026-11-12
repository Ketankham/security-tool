# Sentinel dashboard (`apps/web`)

The operator UI for the platform: onboard a target, verify ownership, define
personas and scope, run scans, and watch each **security checkpoint** go from
pending → running → done with findings accumulating live. It is a thin,
typed client over the control-plane API (`apps/api`) — all logic, scanning,
and verification stay in the Python backend.

## Stack

- **Next.js 15** (App Router) + **React 19** + **TypeScript**, no UI framework
  (hand-written CSS in `app/globals.css`).
- Talks to the API over REST. Types in `lib/types.ts` mirror the API's
  Pydantic schemas; the single client is `lib/api.ts`.
- Live status is **polling**, not websockets: the scan view refetches
  `GET /scans/{id}` and its findings every few seconds and stops once the scan
  reaches a terminal state (`lib/usePoll.ts`).

## What's here

| Route | Purpose |
|---|---|
| `/` | Targets list + add a target. |
| `/targets/[id]` | Ownership verification, authorization, scope rules, personas, scans. |
| `/scans/[id]` | **The live board**: every phase with its status, findings by severity, LLM budget. |

The phase board's ordering and labels live in `lib/scan.ts` and mirror the
backend scan state machine (`sentinel_core.state_machine`). The checkpoints a
user cares about map onto phases: **login / onboarding** → `auth_establishing`;
**role escalation / admin-via-API** → `access_control`; **logout** →
`session_checks`.

## Auth (dev stand-in)

The API's real auth (Clerk) isn't wired yet; it trusts an `X-Org-Id` header
(`apps/api/.../deps.get_current_org`). The dashboard stores a chosen org id in
`localStorage` and sends it on every request. The first screen lets you create
an org or paste an existing id. When Clerk lands, `lib/api.ts` is the one place
that swaps the header for a bearer token.

## Running it

```bash
# 1. Backend up (from repo root): postgres + redis + api + worker
make up && make migrate

# 2. Dashboard
cd apps/web
cp .env.example .env.local        # NEXT_PUBLIC_API_BASE=http://localhost:8000
npm install
npm run dev                       # http://localhost:3000
```

For the browser to reach the API cross-origin, the API must allow the
dashboard's origin. That's `CORS_ALLOW_ORIGINS` in the backend `.env`
(defaults to `http://localhost:3000`).

### Production (the Hetzner VPS)

`docker compose up -d --build` builds and runs the `web` service alongside
the API and worker. Put a reverse proxy (Caddy or Traefik) in front for TLS,
point it at `web:3000`, and set two things for the real domain:

- the build arg `NEXT_PUBLIC_API_BASE` (in `docker-compose.yml`) to the API's
  public URL — it is inlined into the browser bundle at build time;
- `CORS_ALLOW_ORIGINS` in the API env to the dashboard's public origin.

## Checks

```bash
npm run typecheck   # tsc --noEmit
npm run build       # production build
```
