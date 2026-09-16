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

93 tests passing; `ruff`, `ruff format --check`, and `mypy` all clean across the
workspace. Everything past recon (auth, crawler, authz/injection/session checks,
verifier, triage, reporter) is a stub package — see docs/05 for the milestone plan.

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

## The one-line strategy

Be the tool that finds **authorization bugs with near-zero false positives**, sell it to
Series A–C SaaS companies who need continuous assurance between pentests, and upsell a
**human-verified report** signed by a real security expert — because that's what actually
closes SOC 2 and enterprise security questionnaires.
