# ADR-0002 — Build vs. adopt open source (esp. the crawler)

- **Status:** Accepted (proposed for team ratification)
- **Date:** 2026-09-15
- **Context:** the meeting's stage-1 note: "decide whether to build [discovery/crawling] from
  scratch or fork an existing open-source repository," and Ketan's action item to research
  candidate repos.

## Decision

**Adopt for breadth; build for the moat. Never fork copyleft into the commercial core.**

- **Adopt** (shell out to MIT-licensed static binaries — don't reinvent solved problems):
  recon (`subfinder`, `dnsx`, `httpx`, `naabu`, `tlsx`), fast static crawling / JS endpoint
  extraction (`katana`), broad template checks (`nuclei`, ~10k community templates), secret
  scanning (`gitleaks`).
- **Build ourselves** (this is the product, and no open-source tool does it well):
  - The **multi-persona authenticated crawler** (Playwright-based) — off-the-shelf crawlers
    are single-session and don't model roles/tenants. This is the moat; we can't outsource it.
  - The **authorization engine** — the replay matrix, layered access oracle, canary tokens.
    Nothing open-source does cross-persona diffing well.
  - The **session-management suite** — including logout-invalidation, which requires driving
    real logout flows.
  - Our **own SQLi detection** (see licence trap) and the deterministic oracle framework.
  - Triage, verification, reporting, the platform.

## Why not fork a full scanner (ZAP / Nuclei-as-a-platform / Wapiti)

- **Licence.** ZAP is Apache-2.0 (usable) but a heavy Java codebase to bend to our will;
  forking it means owning a large surface we didn't design, in a language off our stack.
- **Architecture mismatch.** These are single-session, anonymous-first designs. Our entire
  differentiator is the *relational, multi-persona* model — retrofitting it onto a
  single-session core is more work than building the core we want and *calling* their good
  parts as libraries/binaries.
- **Better as tools than as a base.** `nuclei` and `katana` are fantastic *components* we
  invoke; they're poor *foundations* to inherit.

## The licence trap (flagged explicitly, because it's a real trap)

- **`sqlmap` is GPLv2.** Importing, linking, or bundling it in a commercial product creates a
  copyleft obligation. **We write our own SQLi detection** (~800 LOC, within competence) to
  stay clean. Same rule for any GPL/AGPL dependency touching the core.
- **`nuclei`, `katana`, `subfinder` etc. are MIT** — safe to invoke as separate-process
  binaries. We keep them at arm's length (subprocess, not linked) and normalise their output,
  which also insulates us from their breaking changes.
- **Enforcement:** a CI licence-check gate with an allowlist (`pip-licenses` /
  `license-checker`) fails the build on any GPL/AGPL/unknown-licence dependency. Not a
  one-time audit — a permanent gate.

## Consequences

- Ketan's research action item resolves to: *evaluate the ProjectDiscovery suite + Playwright*,
  not "find one repo to fork." The answer is a **toolchain we orchestrate**, plus a
  **proprietary persona/authz core** we own.
- We get breadth cheaply and keep our engineering focus on the 20% that's actually
  differentiated.
- We take on an integration/normalisation layer (wrapping each binary, parsing its output,
  handling its failure modes and version drift) — a known, bounded cost, far smaller than
  building recon/templates from scratch or owning a forked scanner.
- Arm's-length invocation (subprocess + normalised schema) means a tool going unmaintained is
  a swap, not a rewrite.
