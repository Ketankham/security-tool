# 06 — Safety, Legal & Abuse

We are building a tool that attacks web applications. The same capability that helps a
customer secure *their* app can attack *someone else's*. Getting this wrong is not a bug —
it's an existential and possibly criminal event. This is a first-class product concern, not
an afterthought.

## 1. Authorization to test (the legal gate)

Testing a system you don't own/aren't authorized to test can violate the CFAA (US), the
Computer Misuse Act (UK), and equivalents everywhere. Therefore:

- **Ownership verification is mandatory** before any authenticated or active scan: DNS TXT,
  a file at `/.well-known/`, or a verified meta tag. No exceptions, no "trust me."
- **Explicit authorization acceptance:** the customer affirms, per target, that they own it
  or are contractually authorized to test it. Recorded, timestamped, versioned.
- **The free scan is deliberately limited** to passive/recon-grade checks that don't
  constitute an "attack," and even it requires a light ownership signal to go beyond a single
  page. We do not offer anonymous active scanning of arbitrary domains — that's a tool for
  attackers.
- **Scope is enforced technically, not just contractually** (see §2).

## 2. Blast-radius containment (technical enforcement)

- **Egress-restricted workers:** each scan runs in a container whose network egress is
  restricted to the resolved IPs of the *approved, verified* scope plus our control plane.
  An out-of-scope request cannot physically leave. This protects customers from our bugs and
  us from becoming an attack proxy.
- **Scope guard** checks every request pre-flight; violations are blocked and alerted.
- **Read-only by default;** read-write is explicit, per-target, staging-preferred.
- **Destructive-action guard** ([04 A1](04-edge-cases.md)) prevents data loss.
- **Adaptive rate limiting + target-health auto-pause + emergency stop** prevent self-DoS.
- **Third parties are never tested** — payment providers, IdPs, embedded widgets are
  scope-excluded by default.

## 3. Data handling (we hold the crown jewels)

We store customer login credentials and copies of their app's responses — potentially
including their users' PII. This makes *us* a high-value target.

- **Credentials:** envelope-encrypted, per-org data key, KMS-wrapped; decrypted only in-memory
  in a worker; never logged; **never placed in an LLM prompt** ([01 §6.3](01-architecture.md)).
- **Transcripts:** scrubbed of secrets on write; PII minimised; retention-limited and
  customer-configurable; deletable on request.
- **LLM data boundary:** we send the model *structure and redacted samples*, not raw
  credential values or bulk PII. Use a provider with a zero-retention / no-training
  commitment for API traffic, and document it.
- **Tenant isolation** in our own multi-tenant platform — audited, because it would be
  darkly ironic to ship the authz scanner and then leak across our own tenants.
- **Encryption in transit and at rest** throughout.

## 4. Abuse prevention (don't become attacker infrastructure)

- Ownership verification is the primary defence.
- **Anomaly monitoring:** flag accounts that add many unrelated high-value domains, that fail
  ownership repeatedly, or whose targets don't match their billing identity.
- **KYC-lite** at higher tiers / for sensitive targets.
- **Abuse response runbook:** ability to instantly suspend a scan/account, cooperation path
  for legitimate takedown/law-enforcement requests, and a clear AUP.
- **Rate/volume ceilings** per account to cap how much damage a compromised account could do.

## 5. Our own security posture

We are a security vendor; a breach is doubly fatal (harm + total credibility loss).
- Pentest our own platform before GA and on a schedule (dogfood the product, plus external).
- SOC 2 Type II on our own roadmap (also a sales asset — customers ask).
- Least-privilege everywhere; secrets in a real secrets manager; short-lived worker creds.
- Supply-chain: pinned deps, licence allowlist, container scanning, SBOM.
- Responsible disclosure channel for researchers who find bugs in us.

## 6. Ethical/positioning guardrails

- We market as **defensive** — helping owners secure their own apps. Never as an offensive
  or "hacking" tool.
- No exploitation beyond what's needed to *prove* a finding; we demonstrate, we don't weaponise.
- Findings and reports are confidential to the customer.
- We decline targets we can't verify and accounts that pattern-match abuse, even at the cost
  of revenue. The trust is the business.

## 7. Compliance surface (what customers will ask us for)

DPA, sub-processor list, data-residency options, retention/deletion controls, SOC 2 report,
pentest attestation, and a security page. Have these ready before enterprise conversations;
they're gating, not nice-to-have. The Verified-report tier ([00 §7](00-product-brief.md))
is itself part of *customers'* compliance surface — which is exactly why it sells.
