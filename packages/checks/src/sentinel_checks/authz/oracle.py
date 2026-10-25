"""The layered access oracle (docs/03-check-catalogue.md §4.4).

This is the crux of the whole product's false-positive claim. A 200 to a
persona who should be denied is NOT automatically a finding. We escalate
through cheap deterministic layers and stop at the first confident answer:

    Layer 1 (status):    subject got 401/403/404/3xx/5xx  -> DENIED. Stop.
    Layer 2 (structure): subject's body is clearly not the actor's resource
                         (empty, much smaller, different shape) -> DENIED. Stop.
    Layer 3 (canary):    the actor's unique seeded token appears in the
                         subject's body -> UNAUTHORIZED_ACCESS, deterministic.
    Layer 4 (semantic):  subject got a 200 structurally like the actor's, no
                         canary reachable -> UNAUTHORIZED_ACCESS but
                         non-deterministic (caps the finding at `probable`;
                         the LLM adjudicator that sharpens this is a later
                         extension — it never gets the last word regardless).

A pure function: (actor response, subject response, actor canaries) in, an
OracleResult out. No I/O, no randomness — which is exactly what lets the
Verifier re-run the surrounding replay and expect the same verdict.
"""

from __future__ import annotations

from collections.abc import Sequence

from .models import AccessVerdict, OracleLayer, OracleResponse, OracleResult


# Statuses that mean "the subject was refused" — the Layer-1 negative filter.
# Anything < 200 or >= 300 is treated as not-successful-access here: a 3xx is
# almost always a redirect to a login/error page for a denied identity, and
# counting it as access would be a false positive.
def _is_success(status: int) -> bool:
    return 200 <= status < 300


# Below this fraction of the actor's body size, the subject's 200 is almost
# certainly an empty list / placeholder / "no access" shell rather than the
# actor's actual resource — a Layer-2 negative filter.
_STRUCTURE_MIN_SIZE_RATIO = 0.5
# Bodies at or under this many bytes are too small to carry a resource worth
# calling a data exposure; treat near-empty 200s as denials.
_MIN_MEANINGFUL_BODY = 16


def access_oracle(
    *,
    actor: OracleResponse,
    subject: OracleResponse,
    actor_canaries: Sequence[str],
) -> OracleResult:
    # The actor is the identity that *should* have access. If the actor
    # itself didn't get a clean 200, we have no baseline to judge the
    # subject against — don't manufacture a finding from a broken baseline.
    if not _is_success(actor.status_code):
        return OracleResult(
            AccessVerdict.INCONCLUSIVE,
            OracleLayer.STATUS,
            f"No baseline: actor response was HTTP {actor.status_code}, not 2xx.",
        )

    # --- Layer 1: status ---
    if not _is_success(subject.status_code):
        return OracleResult(
            AccessVerdict.DENIED,
            OracleLayer.STATUS,
            f"Subject correctly refused with HTTP {subject.status_code}.",
        )

    # --- Layer 3: canary (checked before structure: a canary hit is the
    # strongest signal and should win even if sizes happen to differ) ---
    for token in actor_canaries:
        if token and token in subject.text:
            return OracleResult(
                AccessVerdict.UNAUTHORIZED_ACCESS,
                OracleLayer.CANARY,
                "Actor's unique canary token appeared in the subject's response — "
                "the subject can see data it must not. Isolation is broken.",
                canary_hit=token,
            )

    # --- Layer 2: structure (negative filters) ---
    # Byte-identical responses to two different identities mean the resource
    # is identity-independent — a public or non-sensitive page, not the
    # actor's protected data. A *true* data-exposure bypass is what the canary
    # layer above proves; without a canary we cannot tell a public resource
    # from an un-canaried leak, and we refuse to cry wolf. This is a
    # deliberate false-negative-over-false-positive tradeoff (docs/03 §4.4):
    # seeding a canary at onboarding is what closes the gap.
    if subject.text == actor.text:
        return OracleResult(
            AccessVerdict.DENIED,
            OracleLayer.STRUCTURE,
            "Subject and actor received byte-identical responses and no canary was "
            "present — the resource is identity-independent (public/non-sensitive), "
            "not a privilege boundary.",
        )
    if subject.body_len <= _MIN_MEANINGFUL_BODY:
        return OracleResult(
            AccessVerdict.DENIED,
            OracleLayer.STRUCTURE,
            f"Subject's 2xx body is near-empty ({subject.body_len} bytes) — "
            "not the actor's resource.",
        )
    if actor.body_len > 0 and subject.body_len < actor.body_len * _STRUCTURE_MIN_SIZE_RATIO:
        return OracleResult(
            AccessVerdict.DENIED,
            OracleLayer.STRUCTURE,
            f"Subject's body ({subject.body_len} bytes) is far smaller than the "
            f"actor's ({actor.body_len} bytes) — likely an empty/placeholder view, "
            "not the protected resource.",
        )

    # --- Layer 4: semantic (ambiguous middle) ---
    # Subject got a substantial 2xx, comparable in size to the actor's, with
    # no canary available to prove it. This is a real candidate but not a
    # deterministic proof: cap it at `probable`. (A seeded canary on this
    # endpoint, or the future LLM adjudicator, would resolve it either way.)
    return OracleResult(
        AccessVerdict.UNAUTHORIZED_ACCESS,
        OracleLayer.SEMANTIC,
        f"Subject received a substantial 2xx response ({subject.body_len} bytes) "
        "comparable to the actor's, and no canary was seeded on this endpoint to "
        "prove data exposure deterministically. Probable, pending re-verification.",
    )
