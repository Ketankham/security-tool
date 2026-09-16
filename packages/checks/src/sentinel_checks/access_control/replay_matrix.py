"""The replay matrix (docs/03-check-catalogue.md §4.1-4.2): for a request
observed as persona P, which other personas *should* be denied the same
request?

Grouped by denied persona rather than emitted per-boundary: a persona can
qualify as both vertical- and horizontal-denied for the same P (lower
trust_rank *and* a different tenant), and the caller replays that persona's
session exactly once, then labels the single response with every boundary
it violates — not once per boundary, which would double the live traffic
for no new signal.
"""

from __future__ import annotations

from collections.abc import Sequence

from .models import ANONYMOUS_IDENTITY, ANONYMOUS_PERSONA_ID, Boundary, PersonaIdentity


def personas_that_should_be_denied(
    requesting: PersonaIdentity, all_personas: Sequence[PersonaIdentity]
) -> list[tuple[PersonaIdentity, list[Boundary]]]:
    boundaries_by_id: dict[str, list[Boundary]] = {}
    identities_by_id: dict[str, PersonaIdentity] = {}

    for other in all_personas:
        if other.persona_id == requesting.persona_id:
            continue
        boundaries: list[Boundary] = []
        if other.trust_rank < requesting.trust_rank:
            boundaries.append("vertical")
        if (
            requesting.tenant_key is not None
            and other.tenant_key is not None
            and other.tenant_key != requesting.tenant_key
        ):
            boundaries.append("horizontal")
        if boundaries:
            boundaries_by_id[other.persona_id] = boundaries
            identities_by_id[other.persona_id] = other

    # The anonymous boundary is synthetic — it's never one of the caller's
    # own personas, so it's added unconditionally whenever P is themselves
    # authenticated (docs/03 §4.1: "Q = anonymous (trust_rank 0)").
    if requesting.trust_rank > 0:
        boundaries_by_id.setdefault(ANONYMOUS_PERSONA_ID, []).append("anonymous")
        identities_by_id[ANONYMOUS_PERSONA_ID] = ANONYMOUS_IDENTITY

    return [(identities_by_id[pid], boundaries) for pid, boundaries in boundaries_by_id.items()]
