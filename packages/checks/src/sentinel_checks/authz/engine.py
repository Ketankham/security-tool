"""AuthorizationEngine: the replay matrix executor (docs/03 §4.2–4.4).

Given the requests each persona made during its own crawl, it replays each
authenticated actor's requests as every identity that *should be denied*
them — swapping only the session, nothing else about the request — runs the
layered access oracle on the result, and sends every positive through the
Verifier before it can be labelled confirmed.

    engine = AuthorizationEngine(http=http_engine, sessions=sessions)
    findings = await engine.run(observed=observed, personas=personas)

Read-only by default: only idempotent methods are replayed, so the matrix
never mutates the target (docs/06 blast-radius discipline). The HttpEngine's
scope guard and destructive-action guard still apply to every replay as a
second line of defence.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence

import structlog
from sentinel_core.http_engine import (
    AnonymousSession,
    EngineResponse,
    HttpEngine,
    ScopeViolation,
    SessionState,
)
from sentinel_verifier import ReproductionAttempt, Verifier

from .matrix import personas_that_should_be_denied
from .models import (
    AccessVerdict,
    AuthzBoundary,
    AuthzFinding,
    Confidence,
    EvidenceItem,
    ObservedRequest,
    OracleLayer,
    OracleResponse,
    OracleResult,
    PersonaProfile,
    Severity,
)
from .oracle import access_oracle

log = structlog.get_logger(__name__)

_IDEMPOTENT_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})

_BOUNDARY_RULE_ID = {
    AuthzBoundary.VERTICAL: "authz.vertical",
    AuthzBoundary.HORIZONTAL: "authz.horizontal",
    AuthzBoundary.ANONYMOUS: "authz.anonymous",
}

_BOUNDARY_TITLE = {
    AuthzBoundary.VERTICAL: "Vertical privilege escalation",
    AuthzBoundary.HORIZONTAL: "Cross-tenant access (horizontal)",
    AuthzBoundary.ANONYMOUS: "Unauthenticated access to protected resource",
}


def _severity(boundary: AuthzBoundary, oracle: OracleResult) -> Severity:
    # A deterministic canary hit proves data exposure — the serious cases.
    if oracle.layer is OracleLayer.CANARY:
        if boundary in (AuthzBoundary.HORIZONTAL, AuthzBoundary.VERTICAL):
            return Severity.CRITICAL
        return Severity.HIGH  # anonymous reaching confirmed data
    # Semantic (probable) findings are real candidates but unproven — medium.
    return Severity.MEDIUM


class AuthorizationEngine:
    def __init__(
        self,
        *,
        http: HttpEngine,
        sessions: Mapping[str, SessionState],
        verifier: Verifier | None = None,
        include_write_methods: bool = False,
    ) -> None:
        self._http = http
        self._sessions = dict(sessions)
        self._sessions.setdefault("anonymous", AnonymousSession())
        self._verifier = verifier or Verifier()
        self._include_write = include_write_methods

    async def run(
        self,
        *,
        observed: Sequence[ObservedRequest],
        personas: Sequence[PersonaProfile],
    ) -> list[AuthzFinding]:
        by_id = {p.id: p for p in personas}
        findings: list[AuthzFinding] = []

        for req in self._dedup(observed):
            actor = by_id.get(req.persona_id)
            if actor is None or actor.is_anonymous:
                # Only an authenticated actor's request defines a protected
                # resource others might wrongly reach. Anonymous has none.
                continue
            if not self._replayable(req.method):
                continue

            subjects = personas_that_should_be_denied(actor, personas)
            if not subjects:
                continue

            actor_resp = await self._replay(req, actor)
            if actor_resp is None:
                continue  # replay error — no baseline, skip this request

            for subject, boundary in subjects:
                if subject.id not in self._sessions:
                    log.info("authz.no_session_for_subject", subject=subject.id)
                    continue
                finding = await self._test_pair(req, actor, actor_resp, subject, boundary)
                if finding is not None:
                    findings.append(finding)

        return findings

    def _replayable(self, method: str) -> bool:
        return self._include_write or method.upper() in _IDEMPOTENT_METHODS

    @staticmethod
    def _dedup(observed: Sequence[ObservedRequest]) -> list[ObservedRequest]:
        """One replay per (actor, method, concrete url) — the crawl can report
        the same request many times."""
        seen: set[tuple[str, str, str]] = set()
        out: list[ObservedRequest] = []
        for r in observed:
            key = (r.persona_id, r.method.upper(), r.url)
            if key in seen:
                continue
            seen.add(key)
            out.append(r)
        return out

    async def _replay(self, req: ObservedRequest, who: PersonaProfile) -> EngineResponse | None:
        session = self._sessions.get(who.id)
        if session is None:
            return None
        try:
            return await self._http.request(
                req.method,
                req.url,
                persona=session,
                body=req.body if self._include_write else None,
            )
        except ScopeViolation as exc:
            log.info("authz.replay_scope_blocked", url=req.url, who=who.id, reason=str(exc))
            return None
        except ConnectionError as exc:
            log.info("authz.replay_connection_error", url=req.url, who=who.id, error=str(exc))
            return None

    async def _test_pair(
        self,
        req: ObservedRequest,
        actor: PersonaProfile,
        actor_resp: EngineResponse,
        subject: PersonaProfile,
        boundary: AuthzBoundary,
    ) -> AuthzFinding | None:
        subject_resp = await self._replay(req, subject)
        if subject_resp is None:
            return None

        oracle = access_oracle(
            actor=_as_oracle(actor_resp),
            subject=_as_oracle(subject_resp),
            actor_canaries=actor.canary_tokens,
        )
        if not oracle.is_finding:
            return None

        verification = await self._verify(req, actor, subject, oracle)

        confirmed = oracle.deterministic and verification.passed
        confidence = Confidence.CONFIRMED if confirmed else Confidence.PROBABLE

        evidence = (
            EvidenceItem(
                actor_resp.transcript_id,
                f"request-as-{actor.role_name}",
                f"{actor.label} (trust {actor.trust_rank}) accessed this legitimately.",
            ),
            EvidenceItem(
                subject_resp.transcript_id,
                f"replay-as-{subject.role_name}",
                f"{subject.label} reached it when it should have been denied "
                f"({boundary.value}). {oracle.reason}",
            ),
        )

        return AuthzFinding(
            rule_id=_BOUNDARY_RULE_ID[boundary],
            boundary=boundary,
            title=_BOUNDARY_TITLE[boundary],
            severity=_severity(boundary, oracle),
            confidence=confidence,
            actor_persona_id=actor.id,
            subject_persona_id=subject.id,
            method=req.method.upper(),
            url=req.url,
            path_template=req.path_template,
            oracle=oracle,
            evidence=evidence,
            reproduction={
                "method": req.method.upper(),
                "url": req.url,
                "as_identity": subject.label,
                "expected": "401/403/404 (denied)",
                "observed": f"HTTP {subject_resp.status_code} via {oracle.layer.value} oracle",
            },
            verification=verification.details,
        )

    async def _verify(
        self,
        req: ObservedRequest,
        actor: PersonaProfile,
        subject: PersonaProfile,
        first: OracleResult,
    ):
        """Independently re-execute the replay and require the same positive
        verdict each time. A canary finding must re-hit the same canary; a
        semantic finding must stay a (semantic) unauthorized-access."""

        async def reproduce(i: int) -> ReproductionAttempt:
            actor_resp = await self._replay(req, actor)
            subject_resp = await self._replay(req, subject)
            if actor_resp is None or subject_resp is None:
                return ReproductionAttempt(False, detail="replay failed during re-verification")
            result = access_oracle(
                actor=_as_oracle(actor_resp),
                subject=_as_oracle(subject_resp),
                actor_canaries=actor.canary_tokens,
            )
            same = (
                result.verdict is AccessVerdict.UNAUTHORIZED_ACCESS
                and result.layer is first.layer
                and result.canary_hit == first.canary_hit
            )
            return ReproductionAttempt(
                reproduced=same,
                detail=f"attempt {i}: {result.layer.value} / {result.verdict.value}",
                observed={"status": subject_resp.status_code, "layer": result.layer.value},
            )

        return await self._verifier.verify(reproduce)


def _as_oracle(resp: EngineResponse) -> OracleResponse:
    return OracleResponse(status_code=resp.status_code, text=resp.text)
