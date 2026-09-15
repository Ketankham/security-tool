# ADR-0001 — Engine split: where AI goes, and where it must not

- **Status:** Accepted (proposed for team ratification)
- **Date:** 2026-09-15
- **Context:** the 8 Sep 2026 meeting left open "the ratio of traditional automated security
  testing versus AI-driven analysis — pure AI agent or hybrid."

## Decision

**Hybrid, with a hard architectural boundary: AI proposes, deterministic code disposes.**

The LLM is allowed to *decide what to test and where to aim*. It is never allowed to *decide
whether something is a vulnerability*. Every finding shown to a customer is confirmed by a
scripted, reproducible oracle a human could re-run by hand.

## Why not a pure AI agent

The "autonomous AI pentester" framing is seductive and, for a paid product in 2026, wrong on
three axes:

1. **False positives.** LLMs hallucinate vulnerabilities — they'll call an encoded reflection
   "XSS" and a slow response "SQLi." A security tool's whole value is trust; a false positive
   costs a developer an hour and costs us the account. A deterministic oracle (execute the
   payload, watch the callback fire) has a false-positive rate near zero *by construction*.
2. **Cost & latency.** Running an LLM over every HTTP response on a 50k-endpoint app is both
   slow and a runaway bill. Deterministic checks are microseconds and free.
3. **Reproducibility & defensibility.** When a customer disputes a finding, "the AI thought
   so" loses the argument. "Here's the curl command, run it yourself" wins it. Auditors and
   engineers demand the latter.

## Why not pure traditional automation

Traditional scanners are exactly the commoditised, authz-blind products we're differentiating
*against*. The genuinely hard, genuinely valuable problems are **semantic**:
- "What *should* a viewer be denied?" — requires understanding intent.
- "Is `oid` an object reference worth an IDOR test?" — requires reading meaning, not syntax.
- Automating a snowflake login flow — requires adapting to an unseen UI.
- Writing remediation a developer will actually follow — requires context.

These are where LLMs are genuinely, defensibly better than heuristics. Ceding them to
"traditional automation" means shipping the same weak authz coverage as everyone else.

## The boundary, precisely

| AI is allowed to… | AI is forbidden from… |
|---|---|
| Classify endpoints/parameters by semantic role | Deciding a response *is* a vulnerability |
| Hypothesise the permission model | Emitting a `confirmed` finding |
| Synthesise a login recipe from a DOM | Having its output run as a shell/SQL string unvalidated |
| Plan business-logic test cases | Executing those tests directly |
| Adjudicate genuinely ambiguous response diffs | Being the *last* word (Phase 9 re-verifies deterministically) |
| Write finding narratives & remediation | Setting severity unbounded (adjustment capped at ±1 level) |
| Prioritise where to spend test budget | Seeing raw credentials or bulk PII |

## Consequences

- Every check must define a deterministic oracle before it ships; "the LLM says so" is not an
  oracle. This is a design constraint on Pranav's check spec (M0 deliverable).
- We need the supporting deterministic infrastructure early: OOB callback server, canary
  tokens, session oracle, verification phase. These are load-bearing.
- LLM output is **untrusted input** everywhere: schema-validated, scope-checked, never
  interpolated into a command. Treat the model like a hostile user who occasionally has great
  ideas.
- Cost is controllable: model routing (Haiku bulk / Sonnet mid / Opus high-value) + a hard
  per-scan token budget with graceful degradation to `degraded` rather than a surprise bill.
- This boundary *is* the marketing claim ("near-zero false positives, every finding proven"),
  so it must be real, measured on the benchmark corpus, and never quietly violated under
  schedule pressure.

## The rough ratio (answering the meeting's question directly)

By **volume of work**: ~85% deterministic, ~15% AI.
By **value delivered**: the 15% AI is disproportionately where the differentiation lives
(login automation, authz hypotheses, semantic classification, remediation quality).
So: *mostly-traditional plumbing, AI concentrated at the semantic decision points, with a
deterministic wall between the AI's proposals and the customer's findings.*
