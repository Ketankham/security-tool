# 02 — Scan Lifecycle

This is the meeting's four-stage flow, expanded into the full lifecycle a real scan runs.
Each phase lists its **input**, **what it does**, **which engine (AI/deterministic)**, its
**output**, and the **edge cases that break naïve implementations**.

---

## Phase 0 — Onboarding & scope (one-time per target, human-in-the-loop)

**This phase is where scans succeed or fail.** A tool that makes this easy wins; a tool that
makes it a config nightmare dies in the trial. Invest disproportionately here.

**Steps:**
1. Customer adds a target domain.
2. **Ownership verification** (mandatory, legal gate): DNS TXT record, a file at
   `/.well-known/`, or a meta tag. No scan of an authenticated surface runs until ownership
   is proven and the customer has accepted the authorization terms. See [06](06-safety-legal-abuse.md).
3. **Scope definition:** include/exclude rules (hosts, path prefixes, methods). Sensible
   defaults from the recon pass, editable. A destructive-action denylist (see below).
4. **Persona setup** — the make-or-break UX:
   - Customer provides ≥1 login. We *strongly* prompt for ≥2 roles and, for multi-tenant
     apps, a second-tenant account (this unlocks horizontal IDOR testing).
   - For each, the **AI-assisted login recorder** drives a real browser, the customer logs
     in once (or provides credentials + TOTP secret / a magic-link mailbox), and we record a
     replayable `LoginRecipe`.
   - We immediately establish the **session oracle** by making an authenticated and an
     anonymous request and diffing them. If we can't build an oracle, we tell the customer
     now — not after a useless scan.
   - Customer optionally declares `expected_denied` assertions ("viewers must never reach
     billing") — these become high-signal targeted tests.
5. **Blast-radius policy:** read-only vs. read-write testing, rate ceiling, allowed testing
   window, and whether the target is production or staging (staging strongly recommended).

**Edge cases handled here:**
- CAPTCHA / bot protection on login → offer manual-session import (customer pastes a session)
  or an allowlist request for our scanner IPs.
- SSO/OAuth to a third-party IdP → record the redirect dance; never test the IdP itself
  (out of scope, not theirs).
- MFA → TOTP secret storage, or a per-persona mailbox for email codes.
- Short session TTLs → oracle-driven re-login mid-scan.

---

## Phase 1 — Discovery & Recon *(meeting stage 1, part 1)*

**Input:** verified root domain, scope rules.
**Engine:** deterministic (adopted tools), thin AI classification at the end.

1. **Passive subdomain enumeration** — `subfinder` (never brute-force by default; noisy and
   scope-risky).
2. **Resolution & liveness** — `dnsx`, wildcard detection to avoid poisoning the asset list.
3. **HTTP probing** — `httpx`: status, title, tech fingerprint, TLS, redirects.
4. **Port scan** — `naabu`, **opt-in and scope-gated** (many customers contractually can't
   have their infra port-scanned).
5. **Passive intel** — technology stack, WAF/CDN detection (changes how we throttle),
   `robots.txt`/`sitemap.xml`, exposed `.git`/`.env`/backup files.
6. **AI classification:** cluster assets ("this is the marketing site, this is the app, this
   is the API, this is the admin panel") to prioritise depth. Cheap model, one call.

**Output:** the asset inventory — the scope for everything downstream.

**Edge cases:** wildcard DNS inflating the asset list; shared-hosting/CDN IPs we must **not**
scan (belong to Cloudflare/AWS, not the customer); staging environments discovered that are
out of scope; rate-limited DNS.

---

## Phase 2 — Authentication Establishment *(meeting stage 2, part 1)*

**Input:** personas + login recipes from onboarding.
**Engine:** deterministic replay of recorded recipes; AI only on failure.

1. For each persona, replay its `LoginRecipe` in an isolated browser context.
2. Persist `storage_state` (cookies, localStorage, tokens) encrypted.
3. Verify with the session oracle. **If the oracle fails, do not proceed as that persona** —
   re-run the AI recorder once, and if still failing, mark the persona `unavailable` and
   surface it clearly rather than silently scanning logged-out.
4. Extract the auth mechanism itself for Phase 5 (cookie? bearer JWT? both? where's it stored?).

**Also tested here (authentication *quality*, distinct from *authorization*):**
- Password policy, credential-stuffing resistance signals, rate-limiting on login,
  username enumeration (differential responses / timing), password-reset token strength,
  "remember me" token handling, default/weak credentials on admin panels.

**Edge cases:** login flow changed since last scan (recipe version bump + notify);
rotating CSRF tokens; device-fingerprint / risk-based auth that flags our scanner as
suspicious; account lockout from our own testing (throttle and use dedicated test accounts);
session-per-tab apps.

---

## Phase 3 — Crawling & Surface Mapping *(meeting stage 1, part 2)*

**Input:** authenticated sessions, asset inventory.
**Engine:** deterministic crawl; AI classification of the resulting surface.

**Crawl as *each* persona separately** — this is the step that makes cross-role diffing
possible, and it's why we can't just reuse an off-the-shelf crawler unmodified.

1. **Rendered crawl** — Playwright drives a real browser per persona: executes JS, fires
   events, follows SPA route changes, submits discovered forms with safe values.
2. **Static extraction** — `katana` + JS-bundle parsing to pull API endpoints, route tables,
   and hardcoded paths the DOM never reveals (this catches admin endpoints not linked in the
   member UI — pure gold for authz testing).
3. **API discovery** — intercept XHR/fetch; ingest OpenAPI/Swagger/GraphQL introspection if
   exposed. Build a per-persona endpoint+parameter model.
4. **Surface normalisation** — collapse `/users/123` and `/users/456` into the template
   `/users/{id}`; classify parameters (see below).
5. **AI parameter classification:** for each parameter, label it — object reference (IDOR
   candidate), tenant key, role/permission field, redirect target, file path, raw HTML sink,
   query filter. This labelling *targets* later phases so we don't test blindly.

**Output:** a per-persona surface map + a unified, deduplicated endpoint model annotated with
parameter semantics. **The diff between persona surface maps is the first cheap signal of a
privilege boundary.**

**Edge cases:** infinite crawls (calendars, pagination, faceted search) — depth/breadth caps
+ URL-similarity dedup; **destructive links** (`/delete`, `/logout`, `/deactivate`) — the
**destructive-action guard** must recognise and quarantine these *before* clicking (getting
this wrong deletes customer data — see [04](04-edge-cases.md)); logout links ending the
session mid-crawl; rate limits; client-side-only routes; WebSockets; file-upload forms.

---

## Phase 4 — Passive & Configuration Checks

**Input:** all transcripts collected so far (free — no new requests).
**Engine:** deterministic rules over already-captured traffic.

Security headers (CSP, HSTS, X-Frame-Options, etc.), cookie flags (HttpOnly, Secure,
SameSite), CORS misconfiguration (the `Origin: evil.com` reflection test), TLS/cipher
grading (`tlsx`), information disclosure (stack traces, server banners, verbose errors,
source maps in prod), secrets in JS bundles (`gitleaks`), and the full `nuclei` community
template run (CVEs, default creds, exposed panels, known misconfigs).

These are **table stakes** — cheap, high-volume, low-differentiation. They exist so we look
like a complete product and so the free scan has something to show. They are not the moat.

---

## Phase 5 — Active Injection Testing

**Input:** endpoint model with AI parameter labels.
**Engine:** **deterministic** payloads + **deterministic** oracles. AI *targets*, never *judges*.

Classes: reflected/stored/DOM XSS, SQLi (boolean/error/time — our own code, not GPL sqlmap),
SSTI, SSRF, path traversal, open redirect, command injection, XXE, insecure deserialization
signals, unrestricted file upload, mass assignment.

**The rule that keeps false positives near zero:** every class has a deterministic oracle.
XSS is confirmed by executing the payload in a real browser and observing our unique callback
fire — not by string-matching a reflection. Time-based SQLi requires a statistically
significant, repeated delay differential, not one slow response. **The LLM chooses *where* to
aim and *which* payloads are plausible for the detected stack; it never decides whether a
result is a vulnerability.**

**Blast-radius discipline:** on read-write targets, mutating payloads run only against
records the persona owns or against a customer-provided sandbox dataset. Stored-XSS probes
use uniquely-tagged, self-identifying, reversible content and we track/clean them.

**Edge cases:** WAF blocking (detect, back off, report "WAF present" rather than pretend
clean); rate limits distorting time-based oracles (calibrate baseline latency first, per
endpoint); payloads that trigger real emails/webhooks/charges (the destructive denylist
covers these too); self-DoS from aggressive fuzzing.

---

## Phase 6 — Access Control & Authorization ★ *(meeting stage 3 — the core)*

**Input:** per-persona surface maps, the endpoint model, `trust_rank` + `tenant_key`.
**Engine:** **deterministic replay**; AI only to adjudicate genuinely ambiguous diffs.

This is the product. Full mechanics in [03 §4](03-check-catalogue.md). In outline:

1. **Build the replay matrix.** For every request observed for persona *P*, enumerate the
   personas that *should be denied*: all lower `trust_rank` (vertical escalation), all
   different `tenant_key` (horizontal / cross-tenant IDOR), and anonymous.
2. **Replay** each request with each denied persona's session substituted — same method,
   same body, same everything except identity.
3. **Judge with the layered access oracle:** identical status *and* structurally identical
   body *and* (where seeded) the presence of persona *P*'s **canary token** in persona *Q*'s
   response = confirmed unauthorised access. Ambiguous middle cases (different status but
   partial data) escalate to an LLM adjudicator, and anything it flags is then
   **deterministically re-verified** before it can become a `confirmed` finding.
4. **Parameter-level IDOR sweep:** for endpoints with object-reference parameters, swap in
   IDs known to belong to another persona/tenant and apply the same oracle.
5. **Forced browsing:** feed each persona the *other* personas' discovered-but-unlinked
   endpoints (especially admin routes found via JS extraction) and see what answers.
6. **Function-level checks:** method tampering (`GET`→`POST`/`PUT`/`DELETE`), missing
   function-level access control on API actions, mass-assignment of privilege fields
   (`role: admin`).

**Why this needs the persona model and can't be bolted onto a normal scanner:** the entire
signal is *relational* — it only exists in the comparison between what two identities can do.
A single-session scanner is structurally blind to it.

---

## Phase 7 — Session Management ★ *(meeting stage 3 — session checks)*

**Input:** captured auth mechanism, live persona sessions.
**Engine:** deterministic state manipulation with oracle checks.

- **Logout invalidation** (the meeting called this out specifically): capture a valid session
  token, log out through the UI, then replay the token. If it still works → the server isn't
  invalidating sessions on logout. High severity, extremely common, and *impossible to detect
  without driving the real logout flow* — a differentiator in itself.
- **Session fixation:** does the session ID rotate on privilege change / login?
- **Idle & absolute timeout** behaviour.
- **Concurrent sessions:** does password change / logout kill other sessions?
- **JWT-specific:** `alg:none` acceptance, weak signing secret, unverified signature,
  missing `exp`, sensitive claims, replay after logout, algorithm-confusion (RS256→HS256).
- **Cookie security** for session cookies specifically (overlaps Phase 4 but judged here in
  the session context).
- **CSRF:** presence and validation of anti-CSRF tokens on state-changing requests.

**Edge cases:** distinguishing genuine server-side invalidation from client-side-only logout
(the classic false negative — the UI forgets the token but the server still honours it);
stateless JWTs that are *designed* not to be individually revocable (report the design
trade-off, don't cry wolf); refresh-token rotation schemes.

---

## Phase 8 — Business Logic *(v1.5 — scoped out of first release, designed for now)*

**Engine:** AI plans, deterministic executes. Highest-value, hardest-to-automate, so it's the
Verified-tier and roadmap story rather than v1.

Price/quantity tampering, negative amounts, workflow step-skipping, race conditions
(TOCTOU on limited resources), coupon/discount abuse, quota bypass. The AI reads the app's
purpose and proposes hypotheses; a human (Verified tier) reviews and the engine scripts the
confirmed ones. This is deliberately where the human-expert wedge lives — see [00 §7](00-product-brief.md).

---

## Phase 9 — Verification (non-negotiable gate)

**Input:** every candidate finding.
**Engine:** **purely deterministic. No AI.**

Each candidate is independently re-executed from scratch, ≥2 times. Only findings that
reproduce become `confidence: confirmed`. Non-reproducing candidates are demoted to
`probable` (surfaced separately, never counted in the headline number) or dropped. This phase
is the physical embodiment of the "AI proposes, replay disposes" principle and the reason we
can put a false-positive number on the box.

---

## Phase 10 — Triage, Dedup & Scoring

Fingerprint-based dedup within and across scans (so a recurring bug isn't re-reported as new,
and a fix is detected as `fixed` rather than vanishing silently). Cluster related findings
(20 IDORs on one broken middleware = one root cause, reported once with 20 instances).
Deterministic CVSS from a rule table, with a bounded AI adjustment for exploitability
context. Map every finding to CWE + OWASP Top 10.

---

## Phase 11 — Reporting & Delivery

**Engine:** AI narrative over deterministic data; expert review on the Verified tier.

Per finding: what it is, the **replayable proof** (curl + transcript), business impact,
framework-specific remediation, references. Formats: dashboard, PDF (exec summary + technical
detail), **SARIF** (for GitHub code-scanning / CI gating), and integration pushes (Jira,
Linear, GitHub Issues, Slack, webhook). Trend view across scans. On the Verified tier, the
signed attestation letter (see [00 §7](00-product-brief.md)).

**The delivery principle:** a finding a developer can't act on is noise. Every report item is
one click from a reproduction and a concrete fix. Optimise for *time-to-fix*, not
finding-count — finding-count is a vanity metric that rewards false positives.
