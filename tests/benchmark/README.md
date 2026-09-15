# Benchmark corpus

The measurement harness behind the product's central commercial claim
(docs/00-product-brief.md §7, docs/05-v1-roadmap.md success metrics):
**< 5% false-positive rate, > 95% detection rate on planted IDOR/authz
bugs.** See docs/01-architecture.md §8 for the full rationale.

## Status: scaffold only

As of this commit, only Phase 1 (recon — `packages/recon`) is real. The
authz, injection, and session-management engines this corpus exists to
score (`packages/checks`, `packages/verifier`, `packages/triage`) are still
stub packages (docs/05-v1-roadmap.md M2). **Do not read a clean run of
`test_smoke.py` as "the scanner passed the benchmark"** — there is no
scanner yet to pass or fail it. It currently proves only that recon can
reach the fixture apps.

## Fixtures

| Fixture | What it's for | Source |
|---|---|---|
| OWASP Juice Shop | Broad coverage incl. authz/business-logic challenges | `bkimminich/juice-shop` |
| OWASP crAPI | API-focused, BOLA/IDOR by design | `OWASP/crAPI` (own compose file — see `docker-compose.yml`) |
| VAmPI | API authz | `erev0s/vampi` |
| Our own multi-tenant fixture | **The only source of known-good endpoints** — public vulnerable apps only tell you what's broken, never what's correctly protected, and false-positive measurement needs both | `fixtures/` (not yet built — docs/01 §8, M2) |

## Running it

```
docker compose -f tests/benchmark/docker-compose.yml up -d
uv run pytest tests/benchmark -v -m benchmark
```

Skips cleanly (not a failure) if the fixtures aren't reachable — same
graceful-degrade convention as the rest of the test suite.

## What "done" looks like (M2 exit criteria, docs/05 §M2)

- A tracked, versioned score per CI run: detection rate, false-positive
  rate, wall-time, LLM cost per scan, and run-to-run variance (docs/01 §8).
- The custom multi-tenant fixture built and seeded with canary tokens
  (docs/03 §4.4) so horizontal-isolation findings can be verified, not
  just plausible.
- This README's "Status" section rewritten once that's true.
