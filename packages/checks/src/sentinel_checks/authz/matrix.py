"""The replay matrix (docs/03-check-catalogue.md §4.2): for a request a given
actor legitimately made, which other identities *should be denied* it — and
under which boundary?

Pure metadata logic over trust_rank and tenant_key; no network. The engine
takes each (subject, boundary) this yields, replays the actor's request as
the subject, and runs the access oracle on the result.
"""

from __future__ import annotations

from collections.abc import Sequence

from .models import AuthzBoundary, PersonaProfile


def personas_that_should_be_denied(
    actor: PersonaProfile,
    all_personas: Sequence[PersonaProfile],
) -> list[tuple[PersonaProfile, AuthzBoundary]]:
    """Return (subject, boundary) pairs that ought to be refused the actor's
    request. One boundary per subject — the most specific applicable one —
    so a single bypass is reported once, under the right category.

    Priority when several could apply: ANONYMOUS (logged-out) > HORIZONTAL
    (cross-tenant) > VERTICAL (lower privilege). Cross-tenant is ranked above
    vertical because a peer in another tenant touching this data is a tenant-
    isolation break regardless of relative role.
    """
    pairs: list[tuple[PersonaProfile, AuthzBoundary]] = []

    for subject in all_personas:
        if subject.id == actor.id:
            continue  # an identity is never "denied" its own request

        boundary = _classify(actor, subject)
        if boundary is not None:
            pairs.append((subject, boundary))

    return pairs


def _classify(actor: PersonaProfile, subject: PersonaProfile) -> AuthzBoundary | None:
    # Anonymous may reach nothing an authenticated actor reached.
    if subject.is_anonymous and not actor.is_anonymous:
        return AuthzBoundary.ANONYMOUS

    # Both authenticated. A different, known tenant is a horizontal boundary
    # regardless of role — tenant isolation must hold between peers.
    if (
        not subject.is_anonymous
        and actor.tenant_key is not None
        and subject.tenant_key is not None
        and subject.tenant_key != actor.tenant_key
    ):
        return AuthzBoundary.HORIZONTAL

    # Same tenant (or tenancy not modelled): a strictly lower-privileged role
    # should not reach a higher-privileged actor's action.
    if not subject.is_anonymous and subject.trust_rank < actor.trust_rank:
        return AuthzBoundary.VERTICAL

    # Equal/higher privilege in the same tenant, or an anonymous actor's
    # request (nothing is "below" anonymous): not a denial expectation.
    return None
