# 03 — Check Catalogue

For each check: **what it is**, **how it's detected**, and **how it's proven** (the oracle).
The proof column is the product. A check without a deterministic oracle doesn't ship as
`confirmed` — it ships as `probable` at most.

Legend: **D** = deterministic, **AI** = model-assisted, **H** = hybrid.

---

## 1. Passive & configuration (table stakes — breadth, not moat)

| Check | Detection | Oracle / proof | Engine |
|---|---|---|---|
| Missing security headers | Inspect captured responses | Header absent across representative sample | D |
| Weak CSP | Parse `Content-Security-Policy` | `unsafe-inline`/`*`/missing directives per rule table | D |
| Cookie flags | Parse `Set-Cookie` | Session cookie lacks HttpOnly/Secure/SameSite | D |
| CORS misconfig | Send `Origin: https://evil.example` | Response reflects it **and** `Allow-Credentials: true` | D |
| TLS/cert issues | `tlsx` | Weak cipher / expired / self-signed / weak protocol | D |
| Info disclosure | Pattern scan of bodies/headers | Stack trace, server version, verbose error, source map in prod | D |
| Exposed files | Probe `.git/HEAD`, `.env`, backups | 200 + content signature | D |
| Secrets in JS | `gitleaks` over bundles | Regex + entropy match | D |
| Known CVEs / misconfig | `nuclei` community templates | Template's own matcher | D |

---

## 2. Authentication quality

| Check | Detection | Oracle / proof | Engine |
|---|---|---|---|
| Username enumeration | Diff responses/timing for valid vs invalid users | Statistically significant differential over N samples | D |
| Login rate-limiting absent | N rapid attempts | No throttling/lockout observed | D |
| Weak password policy | Attempt weak passwords on a test account | Accepted | D |
| Password-reset token weakness | Analyse reset token | Predictable / no expiry / reusable | H |
| Default/weak admin creds | Curated list vs discovered admin panels | Successful login | D |
| MFA bypass signals | Probe MFA step | Step skippable / not enforced server-side | H |

---

## 3. Injection (deterministic payloads, deterministic oracles)

| Check | Detection | Oracle / proof | Engine |
|---|---|---|---|
| Reflected/Stored/DOM XSS | Inject unique-tagged payloads at AI-labelled HTML sinks | **Payload executes in a real browser and our unique callback fires.** Never string-match reflection alone. | D (AI targets) |
| SQL injection | Boolean, error, and time-based probes | Boolean: consistent true/false page divergence. Error: DB error signature. Time: repeated statistically-significant delay vs calibrated baseline. **Own implementation — sqlmap is GPL.** | D |
| SSTI | Template math payloads (`{{7*7}}`→`49`) per detected engine | Evaluated output appears | D |
| SSRF | Inject payloads pointing at our unique callback host | **Our callback server receives the request** (out-of-band oracle) | D |
| Path traversal | `../` sequences at file-path params | Known-file signature returned | D |
| Open redirect | Inject external URL at redirect params | 3xx `Location` to attacker host | D |
| Command injection | OOB + time payloads | Callback fires / calibrated delay | D |
| XXE | Malicious XML entities | OOB fetch / file content returned | D |
| Unrestricted upload | Upload benign-but-typed test file | File stored + served with dangerous content-type | D |
| Mass assignment | Add unexpected fields (`role`, `isAdmin`) to requests | Field takes effect (verified via authz oracle) | H |

**OOB (out-of-band) callback server** is shared infrastructure: a unique-subdomain listener
(à la interactsh) that turns SSRF/blind-injection into deterministic yes/no oracles. Build it
into `packages/core` early — many checks depend on it.

---

## 4. Authorization ★ (the differentiator — detailed)

### 4.1 The four boundaries we test

| Boundary | Question | Generated from |
|---|---|---|
| **Vertical** | Can a lower role do a higher role's action? | `Q.trust_rank < P.trust_rank` |
| **Horizontal** | Can tenant A touch tenant B's data? | `Q.tenant_key != P.tenant_key` |
| **Anonymous** | Can a logged-out user reach authenticated surface? | `Q = anonymous (trust_rank 0)` |
| **Object (IDOR)** | Can any identity reference another's object by ID? | Object-reference params × persona/tenant IDs |

### 4.2 The replay matrix

```
for P in personas:
    for req in observed_requests[P]:              # method, path, body, params
        for Q in personas_that_should_be_denied(P, req):
            resp_Q = replay(req, session=Q.session)   # identity swapped, nothing else
            verdict = access_oracle(req, resp_P=observed_response[P][req], resp_Q=resp_Q, Q=Q)
            if verdict == UNAUTHORISED_ACCESS:
                emit_candidate(rule="authz.<boundary>", P, Q, req, resp_Q)
```

`personas_that_should_be_denied` also incorporates the customer's `expected_denied`
assertions as **must-fail** cases — those get priority and stricter reporting.

### 4.3 The IDOR sweep specifically

For endpoints with object-reference parameters (AI-labelled in Phase 3):
1. Collect real object IDs owned by each persona/tenant (from their own crawl).
2. As persona *Q*, request persona *P*'s object IDs.
3. Also probe ID *predictability*: sequential ints → enumeration risk; UUIDs → lower but not
   zero (still test, they leak via other endpoints).

### 4.4 The layered access oracle — how we avoid false positives here

This is the crux. A `200` to persona *Q* is **not** automatically a finding. We escalate
through cheap→expensive layers and stop at the first confident answer:

```
Layer 1 (status):      Q gets 401/403/404 → NOT a finding. Stop. (cheap, catches most)
Layer 2 (structure):   Q's body structurally == P's body (same shape, same field set)?
                       If clearly different (e.g. Q got an empty list / error page) → NOT a finding.
Layer 3 (canary):      Did P's unique CANARY TOKEN (seeded into P's data at onboarding)
                       appear in Q's response? Present → CONFIRMED unauthorised data exposure.
                       This is the strongest deterministic signal and needs no AI.
Layer 4 (semantic):    Ambiguous middle — different status but partial data, or no canary
                       reachable for this endpoint. Escalate to LLM adjudicator with both
                       redacted responses: "does Q's response contain P-owned data Q shouldn't see?"
Layer 5 (re-verify):   ANYTHING that reached a positive verdict — including every Layer-4
                       LLM judgement — is re-run deterministically in Phase 9 (≥2×) before it
                       can be labelled `confirmed`. The LLM never has the last word.
```

**Canary tokens are what make this rigorous.** At onboarding we seed each persona/tenant with
a unique, benign, searchable string (a profile field, a note, a filename). If tenant B's
response ever contains tenant A's canary, isolation is broken — full stop, no judgement call.
Where the app won't let us seed data, we fall back to Layers 1–2 + LLM, and cap the finding at
`probable` unless Phase 9 reproduces a concrete data leak.

### 4.5 Function-level & method checks

| Check | Detection | Oracle |
|---|---|---|
| Missing function-level AC | Replay privileged API actions as lower roles | Action succeeds (state change confirmed) |
| Method tampering | Swap `GET`↔`POST`↔`PUT`↔`DELETE` | Unexpected method honoured with effect |
| Forced browsing | Feed unlinked/admin endpoints (from JS extraction) to lower personas | Authenticated content returned |
| Privilege field mass-assignment | Inject `role`/`isAdmin`/`plan` into own-profile update | Privilege actually changes (re-auth + oracle) |

---

## 5. Session management ★

| Check | Detection | Oracle / proof | Engine |
|---|---|---|---|
| **No logout invalidation** | Capture token → UI logout → replay token | **Old token still returns authenticated content** (session oracle passes post-logout) | D |
| Session fixation | Compare session ID pre/post login | ID unchanged across privilege boundary | D |
| Idle/absolute timeout | Hold token, replay after interval | Still valid past policy | D |
| Concurrent-session handling | Change password on session A, replay session B | B still valid | D |
| JWT `alg:none` | Forge unsigned token | Accepted | D |
| JWT weak secret | Offline crack common secrets | Signature verifies | D |
| JWT alg confusion | Sign RS256 token with public key as HS256 | Accepted | D |
| JWT missing/ignored claims | Tamper `exp`, `sub`, role claims | Honoured without re-validation | H |
| CSRF | State-changing request without/with forged token | Succeeds cross-origin | D |

The logout-invalidation check deserves emphasis: it was explicitly raised in the founding
meeting, it's endemic in real apps, and it is **invisible to any scanner that doesn't drive
the actual logout flow and then re-use the token**. It's a small feature that demos
extremely well.

---

## 6. Business logic (v1.5, Verified-tier)

Price/quantity/negative-amount tampering, workflow step-skipping, TOCTOU race conditions,
coupon/quota abuse. **AI proposes hypotheses from app understanding; human reviews; engine
scripts the confirmed test.** Deliberately human-in-the-loop — this is the expert wedge, not
a v1 automation claim.

---

## 7. Severity model

Deterministic CVSS 3.1 base from a per-rule table, then a **bounded** AI adjustment for
exploitability context (± up to one severity level, with a written justification the expert
can override). Every finding carries CWE(s) and its OWASP Top-10 category. Consistency is
worth more than nuance here: a customer who sees the same bug scored differently on two scans
stops trusting the tool.
