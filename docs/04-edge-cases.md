# 04 — Edge Cases & Failure Modes

The user asked specifically that all flows and edge cases be covered. These are the ones that
decide whether the product is *sellable* rather than merely *demoable*. They're grouped by the
harm they cause if unhandled.

---

## A. Edge cases that can HARM THE CUSTOMER (highest priority — get these wrong once and you're done)

### A1. Destructive actions during crawl/test
A crawler that clicks every link will eventually click `Delete account`, `Cancel
subscription`, `Deactivate user`, or fire a `POST /api/users/{id}/delete`.
**Mitigations, layered:**
- **Denylist first:** built-in patterns (`/delete`, `/remove`, `/deactivate`, `/cancel`,
  `/logout`, `/purge`, `/reset`) + customer-supplied additions, matched on URL, link text,
  button label, and inferred intent, **before** any interaction.
- **Method awareness:** treat all non-idempotent methods (`POST/PUT/PATCH/DELETE`) as
  suspect; require a positive safety signal before firing during crawl.
- **Read-only default:** the default scan policy is read-only. Read-write testing is an
  explicit opt-in per target, ideally against staging.
- **Blast-radius scoping:** mutating tests run only against records the persona owns or a
  provided sandbox dataset.
- **Reversibility log:** every mutating action is recorded so the customer (and we) can see
  exactly what changed.

### A2. Self-inflicted denial of service
Aggressive fuzzing knocks the target over — during business hours, on production.
**Mitigations:** shared adaptive rate limiter (backs off on 429/503/latency spikes),
concurrency caps, testing windows, target-health monitoring that auto-pauses on error-rate or
latency thresholds, and an emergency "stop this scan now" that halts within seconds.

### A3. Triggering real-world side effects
Payloads that send real emails/SMS, create real support tickets, fire real webhooks, or
initiate real charges. **Mitigations:** the destructive denylist covers notification/payment
endpoints; test data is uniquely tagged and self-identifying; payment/checkout flows require
explicit opt-in and a sandbox/test-mode assertion.

### A4. Polluting the customer's data with test artifacts
Stored-XSS probes, spam records, junk uploads left behind. **Mitigations:** all injected
content is uniquely tagged, tracked in a ledger, and **cleaned up in a teardown phase**; where
cleanup isn't possible we warn before testing and report exactly what was left.

### A5. Account lockout from our own auth testing
Login-security testing locks out the very accounts we need. **Mitigation:** use dedicated
disposable test accounts for destructive auth checks; never lock the customer's real personas;
detect lockout and back off.

---

## B. Edge cases that produce FALSE NEGATIVES (silent failure — the dangerous kind, because it looks like success)

### B1. Silent session expiry mid-scan  ← the classic catastrophe
Session dies at request 500 of 5,000. The scanner keeps going *logged out*, sees `401/403`
everywhere, and reports **"excellent access control, no issues."** The customer ships a
broken app believing it's secure.
**Mitigation:** the **session oracle** (see [01 §6.5](01-architecture.md)) is checked
periodically and before every authz verdict. A failed oracle triggers re-login; a verdict
computed against a dead session is invalid and re-run. **This single mechanism is the
difference between a real authz scanner and a dangerous toy.**

### B2. Crawl coverage gaps
Missed surface = untested surface = false "clean". SPAs behind heavy JS, state-machine wizards,
content behind search-only access, WebSocket APIs, GraphQL, infinite-scroll. **Mitigations:**
real-browser rendering, JS-bundle endpoint extraction, OpenAPI/GraphQL-introspection ingestion,
and an honest **coverage report** — we tell the customer what we reached and what we couldn't,
rather than implying total coverage.

### B3. Oracle can't be established
No reliable authenticated/anonymous differential (e.g. the app returns `200` for everything and
signals auth only in the UI). Authz testing is then unreliable. **Mitigation:** detect this at
onboarding, tell the customer, and either work with them to define a custom oracle or cap authz
findings at `probable` with a clear caveat. **Never silently pretend the test ran.**

### B4. Canary can't be seeded
Some apps won't let us plant identifiable data. **Mitigation:** fall back to structural +
LLM-adjudicated + Phase-9-reproduced evidence, capped at `probable` unless a concrete leak is
reproduced. Be honest about the confidence downgrade.

### B5. WAF masking
A WAF blocks our payloads; we conclude "not vulnerable" when the app underneath is. **Mitigation:**
WAF detection is a first-class result — we report "WAF present, findings behind it are
lower-confidence" rather than a false clean, and offer an allowlisted re-scan.

---

## C. Edge cases that produce FALSE POSITIVES (erode trust — the commercial killer)

### C1. Legitimately shared/public resources flagged as IDOR
Not every cross-user-readable object is a bug — public profiles, shared documents, published
content are *supposed* to be reachable. **Mitigations:** the canary-token oracle only fires on
data that was *seeded as private*; the customer can mark endpoints/resource types as
intentionally public; Layer-4 adjudication considers "is this plausibly public?".

### C2. Idempotent-looking differences that aren't findings
Timestamps, CSRF tokens, nonces, request IDs, personalised ads make two "identical" responses
differ. **Mitigation:** the structural diff normalises known-volatile fields before comparison;
we compare *shape and ownership*, not bytes.

### C3. Reflected-but-not-executed "XSS"
A payload appears in the response but is properly encoded / in a non-executing context.
**Mitigation:** browser-execution oracle only — reflection alone is never a finding.

### C4. Rate-limit noise mistaken for time-based SQLi
A slow response under load looks like an injection delay. **Mitigation:** per-endpoint latency
baselining and repeated statistically-significant measurement before asserting time-based
findings.

### C5. Same root cause reported N times
One broken authz middleware surfaces as 200 IDORs; a customer sees 200 criticals and panics /
disbelieves. **Mitigation:** clustering by root cause — report the pattern once with instances
attached.

---

## D. Authentication & session edge cases (Phase 2/7 specifics)

- **CAPTCHA / bot detection on login** → manual-session import or scanner-IP allowlist request.
- **MFA/TOTP** → per-persona TOTP secret or controlled mailbox for email codes.
- **SSO / OAuth / SAML** → record the redirect dance; **never test the third-party IdP** (not
  the customer's asset — legal and technical out-of-scope).
- **Rotating CSRF tokens / anti-automation nonces** → parse and carry per request.
- **Risk-based / device-fingerprint auth** flags our scanner → coordinate an allowlist or
  test-mode with the customer.
- **Short session TTL / refresh-token rotation** → oracle-driven re-login; handle rotation.
- **Login flow changed since last scan** → recipe replay fails → re-record (AI), version-bump,
  notify. Don't silently scan logged-out (see B1).
- **Session-per-tab / per-request tokens** → model the token lifecycle explicitly per app.

---

## E. Scope, legal & infrastructure edge cases

- **Shared hosting / CDN IPs** resolve to Cloudflare/AWS, not the customer → **never** scan;
  scope by verified ownership, not just DNS resolution.
- **Wildcard DNS** inflates the asset list with non-existent hosts → wildcard detection in recon.
- **Out-of-scope third parties** embedded (payment iframes, analytics, chat widgets) → scope
  guard blocks them; we test the customer's app, not Stripe's.
- **Staging vs production** → detect and label; strongly steer testing to staging; require
  explicit acknowledgement for production read-write.
- **Cloud provider ToS** (AWS/GCP/Azure require notice for some testing) → surfaced in
  onboarding checklist.
- **Multi-region / geo-fenced apps** → scan from an appropriate egress region or coordinate.

---

## F. Scale & operational edge cases

- **Infinite crawl spaces** (calendars, faceted search, pagination) → depth/breadth caps +
  URL-template dedup + similarity detection.
- **Enormous apps** (100k+ endpoints) → template-collapse, sampling with coverage honesty,
  incremental scans that test only what changed since last scan (diff-aware scanning — also a
  cost lever).
- **Long-running scans crossing deploys** → the app changes mid-scan; detect surface drift and
  flag affected findings for re-verification.
- **Concurrent scans on shared infra** → per-target global rate budget so two scans can't
  collectively DoS one customer.
- **LLM cost blowout on a huge app** → hard per-scan token budget with graceful degradation
  (cheaper model → disable optional AI stages → mark `degraded`), never a surprise bill.
- **LLM/provider outage** → deterministic phases continue; AI-dependent phases queue or
  degrade; scan completes with a clearly marked reduced scope rather than failing wholesale.
- **Flaky findings across runs** → the benchmark corpus tracks run-to-run variance; a finding
  that only appears 1-in-3 runs is a bug in *our* tool, surfaced in CI.

---

## G. The meta edge case: trust

Every mitigation above ladders up to one commercial truth: **a security tool that lies —
whether by false positive, false negative, or false confidence — is worse than no tool,
because the customer makes decisions on it.** The honesty mechanisms (coverage reports,
confidence downgrades, "WAF present", "oracle unavailable", `degraded` scans) are not
defensive hedging; they are the product's credibility, and credibility is what a security
buyer is actually purchasing.
