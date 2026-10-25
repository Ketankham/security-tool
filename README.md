# Sentinel — Authenticated Web Application Security Testing

> Working name. See [`docs/00-product-brief.md`](docs/00-product-brief.md) for naming options.

An automated web application security platform that finds the vulnerability classes
scanners consistently miss: **broken access control, IDOR, privilege escalation, and
session-management flaws** — by logging in as multiple real users with different roles
and proving what each one can reach.

Traditional DAST scans as an anonymous stranger. Sentinel scans as your admin, your
member, your viewer, and your other tenant — simultaneously — and diffs the results.

## Origin

This plan expands the 8 September 2026 meeting between Ketan (Developer) and Pranav
(Web Security Expert). The meeting defined a four-stage flow (discovery/crawling →
authentication testing → backend & authorization checks → session management) and left
two decisions open:

1. **How much traditional automation vs. AI?** → answered in [ADR-0001](docs/adr/0001-engine-split-ai-vs-deterministic.md)
2. **Build the crawler from scratch or fork open source?** → answered in [ADR-0002](docs/adr/0002-build-vs-adopt-open-source.md)

## Documents

| Doc | What's in it |
|---|---|
| [00 — Product brief](docs/00-product-brief.md) | Problem, market, ICP, positioning, pricing, go-to-market |
| [01 — Architecture](docs/01-architecture.md) | Engine split, tech stack, services, data model, repo layout |
| [02 — Scan lifecycle](docs/02-scan-lifecycle.md) | Phase-by-phase flow from onboarding to report |
| [03 — Check catalogue](docs/03-check-catalogue.md) | Every check, how it's detected, how it's proven |
| [04 — Edge cases](docs/04-edge-cases.md) | The failure modes that decide whether this is sellable |
| [05 — v1 roadmap](docs/05-v1-roadmap.md) | Milestones, scope boundary, team split, success metrics |
| [06 — Safety, legal & abuse](docs/06-safety-legal-abuse.md) | Authorization, blast radius, data handling, compliance |
| [ADR-0001](docs/adr/0001-engine-split-ai-vs-deterministic.md) | Where AI goes and where it must not |
| [ADR-0002](docs/adr/0002-build-vs-adopt-open-source.md) | What to adopt, what to build, licence traps |

## Status

M0 foundations + a first real vertical slice are built (see commits on this branch,
`git log`). What actually works today:

- **Control plane API** (`apps/api`) — orgs, targets, real ownership verification
  (DNS TXT / well-known file / meta tag), scope rules, personas (credentials
  envelope-encrypted), scans, findings. 19 tests.
- **Recon** (`packages/recon`, docs/02 Phase 1) — DNS + subdomain discovery + HTTP
  probing, for real, with an honest degrade path when `subfinder`/`httpx`/`tlsx`
  aren't installed. 22 tests.
- **Worker** (`apps/worker`) — walks the persisted scan state machine through scope
  verification and recon, then pauses (not a fake "complete") since everything past
  that — auth, crawl, the check engines — is still M1+ work. 3 tests.
- **Shared substrate** (`packages/core`) — HTTP engine, scope guard, rate limiter,
  transcript recorder, the scan state machine, envelope encryption. 44 tests.
- **Data model** (`packages/db`) — the full schema from docs/01 §6, with the
  `confidence=CONFIRMED` invariant enforced at the database layer, not just by
  convention. 5 integration tests.
- **Dashboard** (`apps/web`) — a Next.js 15 / React 19 / TypeScript operator UI:
  onboard a target (ownership verify → authorization → scope → personas), run
  scans, and watch each checkpoint go pending → running → done on a live phase
  board with findings accumulating by severity. Thin typed client over the API;
  all logic stays server-side. See [`apps/web/README.md`](apps/web/README.md).
- **Authorization engine** (`packages/checks/authz`) — the moat (docs/03 §4). The
  replay matrix (who should be denied each persona's request) + the layered
  access oracle (status → canary → structure → semantic) + the per-boundary
  finding builder. Catches vertical/horizontal/anonymous broken-access-control,
  proven deterministically by seeded canary tokens. 18 tests, including an
  end-to-end run against a live multi-tenant fixture.
- **Verifier** (`packages/verifier`) — the check-agnostic re-proof gate: a
  candidate is only `CONFIRMED` after an independent re-execution reproduces the
  same verdict ≥2× (all-must-reproduce, so a flaky verdict never confirms). 7 tests.

110 tests passing without a database (plus the DB-backed integration tests);
`ruff`, `ruff format --check`, and `mypy` all clean across the workspace. Still
stubs: injection/session/passive checks, nuclei, triage,
reporter, integrations — and wiring the authz engine into the worker's
`access_control` phase (persisting findings, reading per-persona observed
requests). See docs/05 for the milestone plan.

### Running it locally

```
uv sync --all-packages          # installs the whole workspace
cp .env.example .env             # then set KMS_MASTER_KEY (see the comment in .env.example)
make up                          # postgres + redis + api + worker via docker compose
make migrate
make test                        # or: make test-unit (no DB needed)
```

`make up` needs a working Docker registry pull — if that's blocked in your
environment, run Postgres/Redis natively and point `DATABASE_URL`/`REDIS_URL` in
`.env` at them instead, then `make api` / `make worker` to run each service directly.

The dashboard runs separately:

```
make web-install                 # installs apps/web node deps (Node 22+)
make web                         # Next.js dev server on http://localhost:3000
```

It calls the API at `NEXT_PUBLIC_API_BASE` (default `http://localhost:8000`) and
sends the dev `X-Org-Id` auth header; the API must list the dashboard's origin
in `CORS_ALLOW_ORIGINS`. `make up` also builds and runs it as the `web` service.

## The one-line strategy

Be the tool that finds **authorization bugs with near-zero false positives**, sell it to
Series A–C SaaS companies who need continuous assurance between pentests, and upsell a
**human-verified report** signed by a real security expert — because that's what actually
closes SOC 2 and enterprise security questionnaires.
