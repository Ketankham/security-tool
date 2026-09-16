# 01 — Architecture

## 1. The governing principle

> **AI proposes. The deterministic replay engine disposes.**

Nothing is ever shown to a customer as a finding unless a scripted, reproducible HTTP
transcript proves it. The LLM may generate the *hypothesis* ("`GET /api/v2/invoices/{id}`
looks like a tenant-scoped object reference, try it as the Globex user"), but the
*confirmation* is always a deterministic replay whose output a human could re-run by hand.

This single rule buys three things at once:
- **Near-zero false positives** — the product's entire commercial claim.
- **Cost control** — the LLM runs on a few thousand tokens of decision-making per scan
  phase, not on every HTTP response.
- **Defensibility** — when a customer disputes a finding, we hand them a curl command.

Everything below follows from it.

## 2. Engine split — what is AI, what is code

| Stage | Engine | Rationale |
|---|---|---|
| Subdomain/port/TLS recon | **Deterministic** | Solved problem, fast tools exist |
| Login flow automation | **AI-assisted, cached** | Every login is a snowflake — this is where AI earns its cost. Recorded once, replayed deterministically after. |
| Crawling / DOM traversal | **Deterministic** | Reproducibility matters more than cleverness |
| Endpoint & parameter *classification* | **AI** | "Is `oid` an object reference? Is `org` a tenant boundary?" is semantic |
| Permission-model hypothesis | **AI** | "What should a `viewer` be denied?" — the core semantic task |
| Injection payload testing | **Deterministic** | Oracle-based; LLMs hallucinate vulns here |
| Access-control replay | **Deterministic** | The proof step |
| Response-difference judgement | **Hybrid** | Structural diff first; LLM only on ambiguous cases |
| Business-logic test planning | **AI** | Requires understanding the app's purpose |
| Business-logic test execution | **Deterministic** | Scripted from the AI's plan |
| Verification / reproduction | **Deterministic** | Non-negotiable |
| Dedup & clustering | **Hybrid** | Rule-based fingerprint, embeddings for near-misses |
| Severity & CVSS | **Deterministic table + AI adjustment** | Consistency beats nuance |
| Report narrative & remediation | **AI** | Genuinely better than templates, and low-risk |

Full reasoning in [ADR-0001](adr/0001-engine-split-ai-vs-deterministic.md).

## 3. Technology choices

### 3.1 Backend

| Concern | Choice | Why, and what we rejected |
|---|---|---|
| Language | **Python 3.12** | The security ecosystem, LLM SDKs, and Playwright all live here. Go would be faster for the crawler, but a two-language split with a 2-person team is a tax we can't afford. Where we need Go speed we shell out to static binaries (see §3.3). |
| API framework | **FastAPI** | Async-native, Pydantic models double as our OpenAPI contract and our validation layer. |
| Task execution | **Celery + Redis** for v1 | Scans are long-running, resumable, multi-step workflows — which is literally Temporal's shape. But Temporal is an ops burden for two people. **Mitigation: model the scan as an explicit state machine persisted in Postgres** (see §5), so Celery is only a dumb executor and migrating to Temporal later is mechanical rather than a rewrite. Revisit at ~50 concurrent scans. |
| Browser automation | **Playwright (Python)** + Chromium | Better auto-waiting, network interception and `storage_state` persistence than Selenium. `storage_state` is what makes multi-persona session handling tractable. |
| Database | **PostgreSQL 16** | JSONB for semi-structured findings, plus `pgvector` later for dedup embeddings. One database, not five. |
| Object storage | **Cloudflare R2** (S3 API) | HTTP transcripts, HAR files, screenshots, DOM snapshots. R2 for zero egress fees — we serve a lot of evidence. |
| Cache/queue | **Redis** | Celery broker, rate-limit token buckets, session-state cache |
| Search | Postgres FTS for v1 | Don't add Elasticsearch until someone asks. |

### 3.2 Frontend

| Concern | Choice | Why |
|---|---|---|
| Framework | **Next.js 15 (App Router) + TypeScript** | Server components for the heavy findings tables; one deployment story |
| UI | **Tailwind + shadcn/ui** | Fast, ownable, no vendor lock; good defaults for dense data |
| Charts | **Recharts** | Sufficient; avoid D3 hand-rolling |
| State/data | **TanStack Query** | Scan status is polling/streaming-heavy |
| Auth | **Clerk** for v1 | Fastest path to orgs + RBAC + magic links. **Trade-off:** enterprise SAML is a pricier tier and migration is painful. WorkOS is the better 3-year answer. Decision: Clerk now, budget a WorkOS migration spike in the quarter we sign our first enterprise deal. |
| Billing | **Stripe** (Checkout + Billing Portal + metered add-ons) | Don't build billing |
| Analytics | **PostHog** (self-host option later) | Product analytics + session replay + feature flags in one |
| Errors | **Sentry** | Both frontend and backend |

### 3.3 Security tooling we adopt (not build)

All MIT-licensed, all single static binaries, all shelled out to from Python workers:

| Tool | Role | Licence |
|---|---|---|
| **subfinder** (ProjectDiscovery) | Passive subdomain enumeration | MIT |
| **dnsx** | DNS resolution, wildcard detection | MIT |
| **httpx** | HTTP probing, tech fingerprint, title/status sweep | MIT |
| **naabu** | Port scanning (opt-in, scope-gated) | MIT |
| **katana** | Fast crawler — used for the *unauthenticated* pass and JS endpoint extraction | MIT |
| **nuclei** | ~10k community templates: CVEs, misconfigs, exposures, default creds | MIT |
| **tlsx** | TLS/certificate inspection | MIT |
| **gitleaks** | Secret patterns, applied to JS bundles and exposed files | MIT |

**Licence trap, flagged explicitly:** `sqlmap` is **GPLv2**. Do not import it, link it, or
bundle it in a commercial product. We write our own SQLi detection (boolean-based,
error-based, and time-based — roughly 800 lines and fully within our competence) rather than
inherit a copyleft obligation. Same caution applies to anything AGPL. Every dependency gets
a licence check in CI via `pip-licenses` / `license-checker` with an allowlist.

Full build-vs-adopt reasoning in [ADR-0002](adr/0002-build-vs-adopt-open-source.md).

### 3.4 AI layer

| Concern | Choice |
|---|---|
| Provider | **Anthropic Claude** (primary). Abstracted behind our own `LLMClient` so a second provider is a config change, not a refactor. |
| Model routing | **Opus 5** — permission-model hypothesis, business-logic planning, ambiguous-diff adjudication (low volume, high value). **Sonnet 5** — login flow synthesis, endpoint/parameter classification, report narrative. **Haiku 4.5** — bulk triage, dedup pre-filter, response summarisation (high volume, cheap). |
| Structured output | Tool-use / JSON schema on every call. Never parse prose. |
| Prompt management | Versioned prompt templates in-repo (`packages/ai/prompts/`), with a golden-set regression suite. A prompt change that regresses the eval set fails CI. |
| Cost control | Hard per-scan token budget, enforced in the `LLMClient`. Exceeding it degrades to a cheaper model, then disables optional AI stages and marks the scan `degraded` rather than failing. |
| Safety | LLM output is treated as **untrusted input**. It never becomes a shell command, a SQL string, or an unvalidated URL. Proposed payloads are validated against a schema and a scope check before execution. |

### 3.5 Infrastructure

| Concern | Choice | Why |
|---|---|---|
| Control plane (API, web) | **Fly.io** for v1 | Cheap, fast deploys, global. Migrate to AWS ECS/EKS when an enterprise buyer asks for a VPC. |
| Scanner workers | **Isolated containers, egress-restricted** | Each scan runs in a container whose network policy permits egress **only to the resolved IPs in the approved scope**, plus our own control plane. This is a hard requirement, not a nice-to-have — see [06](06-safety-legal-abuse.md). |
| Sandboxing | gVisor (or Fly Machines' existing isolation) | We execute attacker-controlled-ish payloads and render hostile HTML in a browser |
| Secrets | Fly secrets → **Infisical or AWS Secrets Manager** as we grow | Customer login credentials are the crown jewels |
| Customer credential storage | **Envelope encryption**, per-org data key, KMS-wrapped | Never at rest in plaintext, never in logs, never in LLM prompts (see §6.3) |
| IaC | **Terraform** | Even on Fly — reproducibility |
| CI/CD | **GitHub Actions** | Test, licence check, container scan, deploy |
| Observability | Sentry + OpenTelemetry → Grafana Cloud | Scan phase timings are a first-class product metric |

## 4. System components

```
                          ┌──────────────────────────────┐
                          │  Next.js Web App (Vercel)    │
                          │  dashboard · findings · setup │
                          └───────────────┬──────────────┘
                                          │ REST + SSE
                          ┌───────────────▼──────────────┐
                          │  FastAPI Control Plane       │
                          │  auth · orgs · targets ·     │
                          │  scans · findings · billing  │
                          └───┬──────────────────────┬───┘
                              │                      │
                  ┌───────────▼─────────┐   ┌────────▼─────────┐
                  │  PostgreSQL         │   │  Redis (Celery)  │
                  │  state machine,     │   │  queues, rate    │
                  │  findings, assets   │   │  buckets         │
                  └─────────────────────┘   └────────┬─────────┘
                                                     │
        ┌────────────────────────────────────────────┴───────────────────────┐
        │                  Scanner Workers (isolated, egress-gated)          │
        │                                                                     │
        │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ │
        │  │  Recon   │ │   Auth   │ │  Crawl   │ │  Active  │ │  Authz   │ │
        │  │  Worker  │ │  Worker  │ │  Worker  │ │  Worker  │ │  Worker  │ │
        │  └──────────┘ └──────────┘ └──────────┘ └──────────┘ └──────────┘ │
        │        │            │            │            │            │       │
        │  ┌─────▼────────────▼────────────▼────────────▼────────────▼─────┐ │
        │  │            Shared: HTTP Engine · Scope Guard · Rate            │ │
        │  │            Limiter · Transcript Recorder · LLM Client          │ │
        │  └───────────────────────────────────────────────────────────────┘ │
        └─────────────────────────────┬───────────────────────────────────────┘
                                      │
                       ┌──────────────▼──────────────┐
                       │  Verifier  →  Triage  →      │
                       │  Dedup  →  Reporter          │
                       └──────────────┬──────────────┘
                                      │
              ┌───────────────────────┴────────────────────┐
              │  R2 (transcripts, HAR, screenshots)         │
              │  Integrations (Jira · Linear · GitHub ·      │
              │  Slack · webhooks · SARIF)                   │
              └─────────────────────────────────────────────┘
```

### 4.1 The shared substrate (build this first)

Every worker sits on four shared services. Getting these right on day one prevents a
world of pain later:

1. **HTTP Engine** — the single choke point for every outbound request. Attaches persona
   session state, honours rate limits, records the full transcript, enforces timeouts, and
   retries idempotent requests only.
2. **Scope Guard** — every request is checked against the target's scope rules *before it
   leaves*. Out-of-scope requests are blocked and logged, not merely deprioritised. This is
   the difference between a security product and a liability.
3. **Rate Limiter** — per-target token bucket in Redis, adaptive: backs off on 429/503,
   and on WAF-block signatures. Shared across all workers for one target so five phases
   running concurrently can't collectively hammer a customer.
4. **Transcript Recorder** — writes every request/response pair to R2 with a content-addressed
   key. Findings reference transcript IDs, never inline bodies. This keeps Postgres small
   and makes evidence immutable.

## 5. The scan state machine

Scans are modelled explicitly in Postgres so they survive worker death, can be paused,
resumed, and audited — and so the Celery→Temporal migration stays cheap.

```
QUEUED
  └→ SCOPE_VERIFYING ──(fail)→ BLOCKED_UNVERIFIED
  └→ RECON
       └→ AUTH_ESTABLISHING ──(fail, and auth optional)→ (continue unauthenticated, mark DEGRADED)
                             ──(fail, and auth required)→ FAILED_AUTH
            └→ CRAWLING            (per persona, parallel)
                 └→ SURFACE_MAPPING
                      └→ PASSIVE_CHECKS
                           └→ ACTIVE_INJECTION      ─┐
                           └→ ACCESS_CONTROL        ─┼─ parallel
                           └→ SESSION_CHECKS        ─┤
                           └→ BUSINESS_LOGIC        ─┘  (v1.5)
                                └→ VERIFYING
                                     └→ TRIAGING
                                          └→ REPORTING
                                               └→ COMPLETE
Any state ──→ PAUSED (user, maintenance window, target unhealthy) ──→ resumes
Any state ──→ CANCELLED (user)
Any state ──→ FAILED (unrecoverable; always with a human-readable reason)
```

Every phase writes a `scan_phase` row with `started_at`, `finished_at`, `status`,
`stats_json` and `error`. Phases are **individually resumable** — a crashed active-injection
phase restarts from its checkpoint without re-crawling.

## 6. Data model

### 6.1 Core entities

```
Organization ──┬── User (via Clerk, role: owner|admin|member|viewer)
               ├── Subscription (Stripe)
               └── Target ──┬── ScopeRule      (include/exclude, host/path/method regex)
                            ├── Persona ───── Credential (encrypted)
                            ├── ScanPolicy    (intensity, schedule, windows, blast radius)
                            └── Scan ──┬── ScanPhase
                                       ├── Asset ── Endpoint ── Parameter
                                       ├── Transcript (R2 pointer)
                                       ├── Finding ──┬── Evidence (transcript refs)
                                       │             ├── Verification
                                       │             └── Remediation
                                       └── Report
```

### 6.2 The entity that makes this product work: `Persona`

```python
class Persona:
    id: UUID
    target_id: UUID
    label: str                  # "Acme admin", "Acme viewer", "Globex member"
    role_name: str              # customer's own name for the role
    trust_rank: int             # 0 = anonymous, higher = more privileged.
                                # Drives the vertical-escalation matrix.
    tenant_key: str | None      # personas sharing a tenant_key are in the same
                                # tenant; differing keys are a horizontal boundary
    credential_id: UUID | None  # encrypted; never enters an LLM prompt
    login_recipe: LoginRecipe   # recorded, replayable steps (see §6.4)
    session_state: bytes        # Playwright storage_state, encrypted, TTL'd
    session_oracle: Oracle      # how we know the session is still alive (§6.5)
    canary_tokens: list[str]    # unique strings seeded into this persona's data
    expected_denied: list[str]  # customer-declared "this role must never reach X"
```

`trust_rank` + `tenant_key` together generate the **test matrix**: for every endpoint
discovered by persona *P*, replay as every persona *Q* where
`Q.trust_rank < P.trust_rank` (vertical) or `Q.tenant_key != P.tenant_key` (horizontal),
plus anonymous. That's the whole engine, expressed in two fields.

### 6.3 Credential handling — hard rules

1. Encrypted with a per-org data key; the data key is KMS-wrapped. Rotatable.
2. Decrypted **only** inside a scanner worker, only in memory, never logged.
3. **Never** included in an LLM prompt. The login-recipe AI sees the *DOM structure* with
   values redacted, and emits selectors + a `fill_secret(field, credential_ref)` instruction.
   The worker resolves the reference locally.
4. Transcripts are scrubbed on write: `Authorization`, `Cookie`, `Set-Cookie`, and any
   value matching a known credential are replaced with `«redacted:credential_id»`.
5. Customers can rotate or revoke at any time; revocation invalidates cached session state.

### 6.4 `LoginRecipe` — recorded once, replayed forever

```python
class LoginRecipe:
    strategy: Literal["form", "oauth_redirect", "saml", "api_token", "har_replay", "manual_session"]
    steps: list[Step]        # goto / fill / click / wait_for / solve_totp / read_email_link
    totp_secret_ref: str | None
    email_inbox_ref: str | None     # for magic links — a mailbox we control per persona
    success_assertion: Assertion    # what proves login worked
    max_duration_s: int
    version: int                    # bumped when re-recorded after a UI change
```

Recorded interactively (AI-assisted) at onboarding, then executed deterministically on every
scan. If replay fails, we re-run the AI recorder once, bump the version, and notify the
customer that their login flow changed.

### 6.5 `Oracle` — the most underrated object in the system

An oracle is a cheap, repeatable probe that answers a yes/no question about state. We need
two kinds:

- **Session oracle:** "is persona P still authenticated?" — a request whose response
  provably differs between authenticated and anonymous (e.g. `GET /api/me` → 200 with the
  user's email vs 401). Established during auth onboarding by *actually making both requests
  and diffing them*. Without this, a scan whose session silently expires reports the entire
  app as "properly access-controlled" — a catastrophic false negative that looks like success.
- **Access oracle:** "did persona Q actually receive persona P's data?" — see
  [03 §4.4](03-check-catalogue.md) for the layered approach (status → structural diff →
  canary token → LLM adjudication).

### 6.6 `Finding`

```python
class Finding:
    id: UUID
    scan_id: UUID
    fingerprint: str            # stable hash for dedup across scans: (rule, endpoint_template, param, persona_pair)
    rule_id: str                # "authz.horizontal.idor", "session.no_invalidation_on_logout"
    title: str
    cwe: list[int]
    owasp_top10: str            # "A01:2021"
    cvss_vector: str
    severity: Literal["critical","high","medium","low","info"]
    confidence: Literal["confirmed","probable","informational"]  # "confirmed" REQUIRES a passing Verification
    status: Literal["open","fixed","regressed","accepted_risk","false_positive"]
    evidence_transcript_ids: list[str]
    reproduction: ReproSteps    # includes a copy-pasteable curl
    narrative: str              # AI-written, expert-reviewable
    remediation: Remediation    # framework-aware fix guidance
    first_seen_scan_id: UUID
    last_seen_scan_id: UUID
    verification: Verification | None
```

`confidence == "confirmed"` is gated in code: the ORM refuses to persist it without a linked
`Verification` whose `reproduced_count >= 2`. Make the invariant structural, not cultural.

## 7. Repository layout

Monorepo. One repo, one CI, one version.

```
security-tool/
├── apps/
│   ├── api/                    # FastAPI control plane
│   │   ├── routers/            # targets, scans, findings, personas, billing, webhooks
│   │   ├── models/             # SQLAlchemy
│   │   ├── schemas/            # Pydantic (also the public API contract)
│   │   └── services/
│   ├── worker/                 # Celery workers
│   │   ├── phases/             # one module per scan phase
│   │   └── tasks.py
│   └── web/                    # Next.js
├── packages/
│   ├── core/                   # shared substrate
│   │   ├── http_engine/        # the single outbound choke point
│   │   ├── scope_guard/
│   │   ├── rate_limiter/
│   │   ├── transcript/
│   │   └── state_machine/
│   ├── recon/                  # subfinder/dnsx/httpx/tlsx wrappers
│   ├── crawler/                # Playwright harness + katana bridge + surface mapper
│   ├── auth/                   # login recipes, persona sessions, oracles
│   ├── checks/
│   │   ├── passive/            # headers, cookies, CORS, TLS, disclosure
│   │   ├── injection/          # xss, sqli, ssti, ssrf, traversal, upload, ...
│   │   ├── authz/              # ★ the differentiator
│   │   ├── session/            # ★ logout, fixation, JWT, CSRF
│   │   └── logic/              # v1.5
│   ├── nuclei/                 # template runner + result normaliser
│   ├── verifier/               # deterministic re-proof
│   ├── triage/                 # dedup, severity, clustering
│   ├── reporter/               # PDF, SARIF, narrative
│   ├── integrations/           # jira, linear, github, slack, webhooks
│   └── ai/                     # LLMClient, prompts/, evals/, budget enforcement
├── docs/                       # this plan
├── infra/                      # terraform, fly.toml, Dockerfiles, network policies
└── tests/
    ├── unit/
    ├── integration/
    └── benchmark/              # ★ vulnerable-app corpus — see §8
```

## 8. The benchmark corpus — build this in week 2, not month 5

We cannot claim "near-zero false positives" without measuring. A permanent, versioned suite
of deliberately vulnerable applications, run on every CI build:

- **OWASP Juice Shop** — broad, includes authz and business-logic challenges
- **DVWA**, **bWAPP** — classic injection baselines
- **OWASP crAPI** — API-focused, has BOLA/IDOR by design
- **VAmPI** — API authz
- **A purpose-built multi-tenant SaaS fixture we write ourselves** — the only way to test
  horizontal isolation properly, with known-planted IDORs *and* known-correct endpoints
  that must **not** be flagged

The last one matters most. **False-positive measurement requires known-good endpoints**, and
no public vulnerable app provides them. Budget 3–4 days to build it; it pays for itself
the first time a prospect asks "what's your false-positive rate?" and we answer with a number.

Tracked metrics per build: detection rate per check class, **false-positive rate**, scan
wall-time, LLM cost per scan, and flakiness (variance across 3 identical runs).
