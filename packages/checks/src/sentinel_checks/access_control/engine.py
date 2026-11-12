"""run_access_control: the orchestrator for docs/02-scan-lifecycle.md Phase 6
steps 1-3 (build the replay matrix, replay, judge). Steps 4-6 (the
parameter-level IDOR sweep, forced browsing, function-level/method-tampering
checks) are follow-up work — see the module docstrings in ``models.py`` and
``replay_matrix.py`` for what each depends on that isn't built yet.

Only idempotent (GET) requests are replayed this slice; state-changing
replay needs its own blast-radius discipline (docs/02 Phase 5) and is out of
scope here.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence

from sentinel_core.http_engine import AnonymousSession, HttpEngine, SessionState

from .models import (
    AccessCandidate,
    AccessControlResult,
    ObservedRequest,
    OracleVerdict,
    PersonaIdentity,
)
from .oracle import judge
from .replay_matrix import personas_that_should_be_denied

SessionResolver = Callable[[str], SessionState]


def anonymous_or(resolver: SessionResolver) -> SessionResolver:
    """Wraps a resolver so the synthetic "anonymous" persona_id always
    resolves to AnonymousSession without every caller needing to special-case
    it."""

    def _resolve(persona_id: str) -> SessionState:
        if persona_id == "anonymous":
            return AnonymousSession()
        return resolver(persona_id)

    return _resolve


async def run_access_control(
    *,
    http_engine: HttpEngine,
    observed_requests: Sequence[ObservedRequest],
    personas: Sequence[PersonaIdentity],
    session_for: SessionResolver,
) -> AccessControlResult:
    personas_by_id = {p.persona_id: p for p in personas}
    resolve = anonymous_or(session_for)
    candidates: list[AccessCandidate] = []
    ambiguous_count = 0

    for req in observed_requests:
        if req.method != "GET":
            continue
        requesting = personas_by_id.get(req.requesting_persona_id)
        if requesting is None:
            continue  # e.g. the always-on anonymous crawl — nothing has a lower trust_rank

        denied = personas_that_should_be_denied(requesting, personas)
        if not denied:
            continue

        p_resp = await http_engine.request("GET", req.url, persona=resolve(requesting.persona_id))

        for denied_persona, boundaries in denied:
            q_resp = await http_engine.request(
                "GET", req.url, persona=resolve(denied_persona.persona_id)
            )
            verdict, detail = judge(
                p_status=p_resp.status_code,
                p_body=p_resp.body,
                q_status=q_resp.status_code,
                q_body=q_resp.body,
                p_canary_tokens=requesting.canary_tokens,
            )
            if verdict == OracleVerdict.NOT_A_FINDING:
                continue
            if verdict == OracleVerdict.AMBIGUOUS:
                ambiguous_count += 1
                continue
            for boundary in boundaries:
                candidates.append(
                    AccessCandidate(
                        rule_id=f"authz.{boundary}",
                        boundary=boundary,
                        requesting_persona_id=requesting.persona_id,
                        denied_persona_id=denied_persona.persona_id,
                        request=req,
                        verdict=verdict,
                        denied_status_code=q_resp.status_code,
                        detail=detail,
                        denied_transcript_id=q_resp.transcript_id,
                    )
                )

    return AccessControlResult(candidates=candidates, ambiguous_count=ambiguous_count)
