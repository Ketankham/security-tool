# 00 — Product Brief

## 1. The problem, stated precisely

Broken Access Control has been **#1 on the OWASP Top 10 since 2021**. It is also the
category that automated scanners are worst at. The reason is structural, not incidental:

- An injection bug (XSS, SQLi) has a **local oracle**. You send a payload, you look for a
  reflection, an error, or a time delay. The scanner can verify it alone.
- An access-control bug has **no local oracle**. A `200 OK` is only a vulnerability if the
  user who received it *should not have been allowed to*. That requires knowing the
  application's intended permission model — which lives in somebody's head, not in the HTTP
  response.

So the industry has settled into two unsatisfying options:

| Option | Finds authz bugs? | Cost | Cadence |
|---|---|---|---|
| DAST scanners (Acunetix, Invicti, Probely, Detectify, Qualys WAS) | Barely | $5k–50k/yr | Continuous |
| Human pentest (Cobalt, Bugcrowd, boutique firms) | Yes | $15k–40k per engagement | Twice a year if you're lucky |
| Open source (ZAP, Nuclei, Burp Community) | No | Free + expert salary | Whenever someone has time |

The gap: **continuous, authenticated, authorization-aware testing at software prices.**

## 2. Why now

Three things changed:

1. **Apps became SPAs.** Classic crawlers that follow `<a href>` see almost nothing of a
   React app. You need a real browser driving real events. That's now cheap and reliable
   (Playwright).
2. **LLMs can read an app's intent.** The hard part of authz testing — "what *should* a
   `viewer` be able to do?" — is a semantic question. An LLM reading the UI, the JS bundle,
   the API responses and the role names can form a hypothesis. It can't be trusted to
   *confirm* one, but it doesn't need to: a replay engine can.
3. **Compliance pressure moved downmarket.** Every Series A SaaS selling to mid-market now
   faces SOC 2 and security questionnaires. They need evidence of continuous testing, not
   one PDF a year.

## 3. What we build

**Sentinel** — a multi-persona authenticated security testing platform.

The core mechanic that nothing else does well:

```
1. You give us 2+ logins:  admin@acme.test, member@acme.test, viewer@acme.test
                           and (ideally) a user in a *different tenant*: user@globex.test
2. We log in as each, in a real browser, and keep the sessions alive.
3. We crawl the app as EACH persona — building a separate map per role.
4. We diff the maps. Everything admin can reach that member cannot is a
   candidate privilege boundary.
5. We replay every admin request as member, as viewer, as the other tenant,
   and as an anonymous stranger.
6. Anything that returns the admin's data to the wrong persona is a finding —
   and we hand you the exact HTTP transcript that proves it.
```

Around that core sits everything a buyer expects from a scanner: recon, passive checks,
TLS/headers/cookies, the injection classes, and the ~10,000 community Nuclei templates for
breadth. Those are table stakes, not the differentiator — but without them we don't look
like a real product.

## 4. Positioning

> **"Your scanner tests your app as a stranger. We test it as your users."**

Category: *Authenticated DAST / Continuous Application Penetration Testing.*

We do **not** position as:
- "AI pentester that replaces humans" — overclaims, and every buyer's security lead has
  already been burned by this in 2025/26.
- "Vulnerability scanner" — commoditised, races to the bottom on price.

We **do** position as:
- The tool that finds the bug class your scanner can't and your pentest only samples.
- Zero-false-positive by construction: every finding ships with a replayable proof.

## 5. Ideal customer profile

**Primary (v1):**
- B2B SaaS, Series A–C, 20–200 engineers
- Multi-tenant application with roles (owner/admin/member/viewer is the giveaway)
- Actively pursuing or maintaining SOC 2 Type II / ISO 27001
- Has 0–2 dedicated security people; usually a staff engineer who "owns security"
- Buys with a company card or a light procurement process at <$25k/yr

**Buyer:** Head of Engineering, VP Eng, or the first security hire.
**Champion:** the engineer who got handed the last pentest report.
**Trigger events:** failed a security questionnaire, SOC 2 audit starting, first enterprise
deal in the pipeline, a near-miss incident, a pentest that found an IDOR.

**Explicitly not v1:** regulated enterprise (needs on-prem, SAML, long procurement),
consumer apps without roles, non-web (mobile/desktop), internal apps behind a VPN.

## 6. Competitive landscape

| Player | Strength | Where we win |
|---|---|---|
| **Burp Suite Enterprise** | Gold-standard engine, deep | Configuration burden; authz testing still manual via extensions |
| **Invicti / Acunetix** | Proof-based scanning, mature | Anonymous-first; weak on SPA + multi-role; enterprise pricing/process |
| **Detectify** | Great UX, crowdsourced payloads | Surface-monitoring focus; light on authenticated authz |
| **Probely / Intruder** | Developer-friendly, fair price | Breadth over depth; no persona model |
| **StackHawk** | CI-native, dev-first | API-focused, ZAP-based; no cross-role diffing |
| **Pentest-as-a-Service** (Cobalt, Bugcrowd) | Human quality | Point-in-time, 10–30× our price |
| **AI pentest entrants** (XBOW, Horizon3, Terra, Mindfort) | Ambitious, well-funded | Enterprise-priced, infra-focused, or black-box with weak proof trails |
| **ZAP / Nuclei** | Free, powerful | Require an expert; no auth handling, no triage, no report |

**Honest read:** we are not going to out-engineer Burp on payload breadth, and we shouldn't
try. We win on a *single vertical slice done properly* — the multi-persona authorization
engine — plus taste in UX and reporting.

## 7. The wedge that makes it sellable: human-verified reports

This is the strategic point that turns a $299/mo tool into a $12k/yr compliance purchase,
and it uses the unfair advantage the founding team actually has (Pranav).

- **Tier 1 (self-serve):** the platform runs, findings appear, you fix them.
- **Tier 2 (verified):** before each quarterly report, Pranav (or a vetted expert) reviews
  the findings, removes noise, adds manual business-logic testing, and **signs** the report.
  The customer gets a letter of attestation they can hand to their auditor or their
  prospect's security team.

Tier 2 is what gets budget approved. The software makes the expert 10× more efficient;
the expert makes the software worth 10× more. Neither works as well alone.

## 8. Pricing

Per-application subscription — predictable, aligns with how customers think about scope.
**Not** per-scan (punishes the behaviour we want) and **not** per-vuln (perverse).

| Plan | Price | Apps | Includes |
|---|---|---|---|
| **Free scan** | $0 | 1 domain | Recon + passive + TLS/headers. No login. Lead magnet. |
| **Starter** | $299/mo | 1 | Full engine, 3 personas, weekly scans, PDF report, Slack |
| **Growth** | $899/mo | 5 | 10 personas, daily scans, Jira/Linear/GitHub, API, SARIF |
| **Scale** | $2,499/mo | 15 | Unlimited personas, CI gating, SSO, priority support, custom checks |
| **Verified report** | $2,500 / report | — | Expert review + manual testing + signed attestation letter |
| **Enterprise** | Custom | — | On-prem/VPC, SAML, DPA, custom SLA |

Annual billing at 2 months free. Land at Starter/Growth, expand on app count and Verified.

**Unit economics sanity check.** The cost driver is scan compute (browser minutes) and LLM
tokens. Budget target: a Growth customer's monthly scans should cost us **< $90** all-in
(10% of revenue) — which requires a hard per-scan token budget and aggressive model routing.
See [ADR-0001 §6](adr/0001-engine-split-ai-vs-deterministic.md).

## 9. Go-to-market

**Lead magnet:** free unauthenticated scan of any domain you can prove you own. Takes 4
minutes, produces a genuinely useful report, ends on "we found 3 things without logging in —
give us a login and we'll show you what's behind the door."

**Content:** own the "broken access control" search term. Deep technical writing:
IDOR taxonomy, multi-tenant isolation testing, why scanners miss authz, JWT session
failures. This audience reads and shares good technical content and ignores everything else.

**Channels, in priority order:**
1. Founder-led sales into the network + warm intros (first 20 customers)
2. Technical content + SEO on the authz/IDOR cluster
3. **Compliance partner channel** — vCISOs and SOC 2 consultancies in the Vanta/Drata
   orbit already own the buyer at the trigger moment and need a pentest partner. This is
   the highest-leverage channel and it's underrated.
4. Open-source a narrow, genuinely useful piece (e.g. the authz matrix replay CLI) to build
   credibility. Keep the persona engine and triage proprietary.
5. Marketplace listings (AWS Marketplace, GitHub Marketplace) once there's an integration.

**Anti-channel:** paid ads. This buyer does not click ads for security tools.

## 10. Naming

Working name `Sentinel` is heavily used. Candidates to check for trademark/domain:
`Personae`, `Roleplay`, `Tenanted`, `Bounds`, `Perimeter`, `Authz`, `Clearance`,
`Impostor`, `Doppel`. Recommendation: something that signals *acting as your users* —
`Doppel` or `Personae` — rather than generic security-menace words.

Decide by end of M1; it blocks domain, Stripe and design work.
