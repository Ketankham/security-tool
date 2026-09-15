# 05 — v1 Roadmap

## The scoping philosophy

A 2-person team (Ketan building, Pranav defining security) cannot out-feature Burp or Invicti.
The only winning strategy is **narrow and deep**: ship the multi-persona authorization +
session engine *better than anyone*, wrap it in enough table-stakes breadth to look like a
real product, and lean on the human-verified report for revenue. Everything that isn't the
moat is either adopted (open source) or deferred.

**v1 is not "a scanner." v1 is "the authorization scanner that happens to also do the basics."**

---

## What ships in v1 (the sellable minimum)

**Must have — the moat:**
- Multi-persona authenticated scanning (≥3 personas + anonymous + cross-tenant)
- AI-assisted login recorder → deterministic replay
- Session oracle (the anti-false-negative mechanism)
- Full authorization engine: vertical, horizontal, anonymous, IDOR, forced browsing,
  function-level, method tampering, mass assignment
- Session-management suite incl. the logout-invalidation check and JWT checks
- Canary-token layered access oracle
- Deterministic verification gate (`confirmed` requires reproduction)

**Must have — to look like a real product:**
- Recon (subfinder/dnsx/httpx/tlsx)
- Rendered crawler (Playwright) + JS endpoint extraction (katana)
- Passive/config checks + full nuclei run
- Core injection classes with deterministic oracles (XSS, SQLi, SSRF, traversal, open
  redirect, SSTI) + the OOB callback server
- Dashboard, findings UI with reproductions, PDF + SARIF export
- Jira/Linear/GitHub/Slack integration (at least one deep, rest via webhook)
- Scheduling, scan history, trend/regression view
- Org/RBAC/billing (Clerk + Stripe)
- **The free unauthenticated scan** (the lead magnet)

**Must have — trust & safety:**
- Ownership verification gate
- Scope guard + egress-restricted workers
- Destructive-action guard + read-only default
- Adaptive rate limiter + emergency stop
- Credential envelope encryption + transcript scrubbing
- The vulnerable-app **benchmark corpus** with tracked FP/FN rates

**Explicitly deferred to v1.5+ (designed for, not built):**
- Business-logic testing automation (stays human/Verified-tier in v1)
- Elaborate AI attack chaining / autonomous exploitation
- Mobile / thick-client / non-web
- On-prem / VPC deployment, SAML SSO (until first enterprise deal)
- GraphQL-deep and gRPC support beyond basic discovery
- Marketplace listings, public API v2, custom-check authoring UI

---

## Milestones (target: sellable v1 in ~5 months, 2 people)

Timelines assume Ketan full-time on build, Pranav part-time on security definition + the
Verified service. They're deliberately conservative; the moat is worth doing slowly and right.

### M0 — Foundations (weeks 1–3)
- Monorepo, CI, licence-check gate, container scanning
- The **shared substrate**: HTTP engine, scope guard, rate limiter, transcript recorder, OOB
  callback server, LLM client with budget enforcement
- Scan state machine in Postgres; Celery wiring
- Benchmark corpus stood up (Juice Shop, crAPI, VAmPI + the custom multi-tenant fixture)
- **Pranav deliverable (the meeting's action item): the detailed check lifecycle spec** —
  every check, its payloads, its oracle, its severity. This is the source of truth M2–M3 build against.

**Exit:** a request can be made through the full substrate, scoped, rate-limited, recorded;
CI runs against the corpus (even if it finds nothing yet).

### M1 — Recon + crawl + auth (weeks 4–7)
- Recon phase (adopted tools, normalised)
- Playwright crawler + JS extraction + surface mapper + parameter classification
- AI login recorder + deterministic replay + **session oracle** + persona model
- Onboarding UX: add target → verify ownership → set scope → set up personas
- **Name/brand decided; domain, Stripe, design system in place**

**Exit:** log in as 3 personas on a real app, crawl each, produce per-persona surface maps.

### M2 — The moat (weeks 8–12)
- Full authorization engine (all four boundaries) + layered access oracle + canary tokens
- Session-management suite incl. logout-invalidation + JWT
- Deterministic verification gate
- Triage: dedup, clustering, CVSS
- Measured against corpus: **publish an internal FP/FN number and drive it down**

**Exit:** on the custom multi-tenant fixture, we find every planted IDOR/authz bug and flag
**zero** known-good endpoints. That number is the product.

### M3 — Breadth + delivery (weeks 13–16)
- Passive/config + nuclei + core injection classes
- Reporting (dashboard, PDF, SARIF), integrations, scheduling, trend view
- Free unauthenticated scan (lead magnet) end-to-end
- Billing live

**Exit:** a stranger can run a free scan; a paying customer can run a full authenticated scan
and get a report they'd act on.

### M4 — Harden + design partners (weeks 17–20)
- 3–5 **design-partner** customers (from the founders' network) on real apps, free, in
  exchange for brutal feedback and a testimonial
- Fix the reality gap between the corpus and messy real apps (this is where the real edge
  cases in [04](04-edge-cases.md) get exercised)
- Verified-report service operationalised (Pranav's workflow, templates, attestation letter)
- Security/pen-test of our own platform (we of all people cannot get breached)
- SOC 2 readiness started for ourselves

**Exit:** paying customers, a repeatable Verified report, a defensible FP number, references.

### Post-v1 — Growth
Business-logic automation, compliance-partner channel, CI-gating polish, enterprise features
as pulled by demand — not pushed by roadmap.

---

## Team split (matches the meeting's action points)

| | Ketan (Developer) | Pranav (Web Security Expert) |
|---|---|---|
| Owns | Architecture, substrate, engine, product, infra | Check definitions, oracles, severity, threat model |
| M0 | Foundations + corpus | **The detailed check lifecycle spec (meeting action item)** |
| M1–M3 | Build every phase | Validate detections; define the crawler adopt-vs-build call (meeting action item); tune payloads |
| M4+ | Harden, scale | Run the Verified-report service (the revenue wedge) |

The meeting's two open questions are resolved in the ADRs:
- AI-vs-traditional ratio → [ADR-0001](adr/0001-engine-split-ai-vs-deterministic.md)
- Build-vs-fork the crawler → [ADR-0002](adr/0002-build-vs-adopt-open-source.md)

---

## Success metrics for v1

| Metric | Target | Why |
|---|---|---|
| **False-positive rate on corpus** | < 5% | The entire commercial claim |
| Authz/IDOR detection rate on corpus | > 95% | The moat works |
| Scan wall-time (mid-size app) | < 2 h | Usable cadence |
| LLM cost per scan | < $5 (Starter), < $9 (Growth) | Unit economics ([00 §8](00-product-brief.md)) |
| Time-to-first-finding (free scan) | < 5 min | Lead-magnet conversion |
| Design-partner → paid conversion | ≥ 3 of 5 | Product-market fit signal |
| Verified reports delivered | ≥ 3 | The revenue wedge is real |

**Anti-metric we refuse to optimise:** total finding count. It rewards false positives and
punishes the honesty that is our actual differentiator.
