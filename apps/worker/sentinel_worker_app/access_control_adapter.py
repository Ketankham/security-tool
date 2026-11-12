"""Bridges DB-persisted Persona rows and crawled SurfaceMaps into
sentinel_checks' plain dataclasses, runs the access-control engine, then
runs every candidate back through the Phase 9 verification gate and
persists the result as Finding/Verification/Evidence rows. Kept as its own
module for the same reason as auth_adapter.py/surface_adapter.py: scan_runner
should read as orchestration, not plumbing.
"""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime

from sentinel_auth import PersonaSession
from sentinel_checks.access_control import (
    ANONYMOUS_PERSONA_ID,
    AccessCandidate,
    ObservedRequest,
    PersonaIdentity,
    run_access_control,
)
from sentinel_checks.access_control.oracle import judge
from sentinel_checks.verification import VerificationOutcome, verify_candidate
from sentinel_core.http_engine import HttpEngine, SessionState
from sentinel_crawler import SurfaceMap
from sentinel_db.enums import FindingConfidence, FindingSeverity, FindingStatus
from sentinel_db.models import Evidence, Finding, Persona, Scan, TranscriptRecord, Verification

# Deterministic per-rule metadata (docs/03-check-catalogue.md §7: consistency
# matters more than nuance — the same bug must score the same way on every
# scan). CVSS vectors and the bounded AI severity adjustment are triage
# work, not built yet; severity here is the rule-table baseline only.
_RULE_TITLE = {
    "authz.vertical": "Vertical privilege escalation",
    "authz.horizontal": "Horizontal / cross-tenant data exposure",
    "authz.anonymous": "Authenticated content reachable without authentication",
}
_RULE_SEVERITY = {
    "authz.vertical": FindingSeverity.HIGH,
    "authz.horizontal": FindingSeverity.HIGH,
    "authz.anonymous": FindingSeverity.CRITICAL,
}
_RULE_CWE = {
    "authz.vertical": [284],
    "authz.horizontal": [639],
    "authz.anonymous": [284],
}


@dataclass(frozen=True, slots=True)
class AccessControlStats:
    observed_requests: int
    candidates_found: int
    ambiguous_skipped: int
    confirmed: int
    probable: int


def _build_persona_identities(
    personas: list[Persona], available_persona_ids: set[str]
) -> list[PersonaIdentity]:
    return [
        PersonaIdentity(
            persona_id=str(p.id),
            trust_rank=p.trust_rank,
            tenant_key=p.tenant_key,
            canary_tokens=tuple(p.canary_tokens),
        )
        for p in personas
        if str(p.id) in available_persona_ids
    ]


def _build_observed_requests(surfaces: list[SurfaceMap]) -> list[ObservedRequest]:
    return [
        ObservedRequest(
            method=endpoint.method,
            url=endpoint.url,
            path_template=endpoint.path_template,
            requesting_persona_id=endpoint.persona_id,
        )
        for surface in surfaces
        for endpoint in surface.endpoints
    ]


def _build_session_resolver(
    *, in_memory_sessions: dict[str, dict], target_host: str
) -> Callable[[str], SessionState]:
    def resolve(persona_id: str) -> SessionState:
        storage_state = in_memory_sessions.get(persona_id, {})
        return PersonaSession(persona_id, storage_state, target_host=target_host)

    return resolve


def _make_reproduce(
    *,
    candidate: AccessCandidate,
    requesting_identity: PersonaIdentity,
    http_engine: HttpEngine,
    session_for: Callable[[str], SessionState],
) -> Callable[[], Awaitable[bool]]:
    async def reproduce() -> bool:
        p_resp = await http_engine.request(
            "GET", candidate.request.url, persona=session_for(candidate.requesting_persona_id)
        )
        q_resp = await http_engine.request(
            "GET", candidate.request.url, persona=session_for(candidate.denied_persona_id)
        )
        verdict, _ = judge(
            p_status=p_resp.status_code,
            p_body=p_resp.body,
            q_status=q_resp.status_code,
            q_body=q_resp.body,
            p_canary_tokens=requesting_identity.canary_tokens,
        )
        return verdict == candidate.verdict

    return reproduce


def _build_transcript_record(*, scan: Scan, candidate: AccessCandidate) -> TranscriptRecord:
    """Evidence.transcript_id has a real FK to transcript_records — a DB
    index over sentinel_core.transcript's content-addressed blob storage
    (docs/01 §4.1 item 4) that nothing has needed to populate before now
    (M1's phases never created Evidence rows). Cross-scan collisions (the
    same content-hash transcript_id already indexed by an earlier scan)
    aren't handled here — a future slice needs an upsert, since this PK is
    content-addressed and legitimately stable across scans."""
    denied_persona_id = (
        None
        if candidate.denied_persona_id == ANONYMOUS_PERSONA_ID
        else uuid.UUID(candidate.denied_persona_id)
    )
    return TranscriptRecord(
        transcript_id=candidate.denied_transcript_id,
        scan_id=scan.id,
        persona_id=denied_persona_id,
        method=candidate.request.method,
        url=candidate.request.url,
        status_code=candidate.denied_status_code,
    )


def _build_finding(
    *, scan: Scan, candidate: AccessCandidate, outcome: VerificationOutcome
) -> Finding:
    fingerprint = Finding.compute_fingerprint(
        rule_id=candidate.rule_id,
        endpoint_template=candidate.request.path_template,
        param="",
        persona_pair=f"{candidate.requesting_persona_id}:{candidate.denied_persona_id}",
    )
    finding = Finding(
        scan_id=scan.id,
        fingerprint=fingerprint,
        rule_id=candidate.rule_id,
        title=_RULE_TITLE[candidate.rule_id],
        cwe=_RULE_CWE[candidate.rule_id],
        owasp_top10="A01:2021",
        severity=_RULE_SEVERITY[candidate.rule_id],
        confidence=FindingConfidence.PROBABLE,
        status=FindingStatus.OPEN,
        reproduction={
            "method": candidate.request.method,
            "url": candidate.request.url,
            "requesting_persona_id": candidate.requesting_persona_id,
            "denied_persona_id": candidate.denied_persona_id,
        },
        narrative=(
            f"Persona '{candidate.requesting_persona_id}' reached a resource that persona "
            f"'{candidate.denied_persona_id}' should have been denied (boundary: "
            f"{candidate.boundary}). {candidate.detail}"
        ),
        remediation={
            "summary": "Enforce an ownership/role check on this endpoint server-side; "
            "identity must never be trusted from a client-supplied ID alone."
        },
        first_seen_scan_id=scan.id,
        last_seen_scan_id=scan.id,
    )
    # Set via the relationship, not a raw finding_id, so the in-memory
    # `finding.verification`/`finding.evidence` are populated immediately —
    # the before_flush invariant in sentinel_db.models.finding reads them
    # off the Python object, not the database.
    finding.verification = Verification(
        reproduced_count=outcome.reproduced_count,
        attempted_count=outcome.attempted_count,
        passed=outcome.passed,
        last_run_at=datetime.now(UTC),
        details={},
    )
    finding.evidence.append(
        Evidence(
            transcript_id=candidate.denied_transcript_id,
            role=f"replay-as-{candidate.denied_persona_id}",
            note=candidate.detail,
        )
    )
    if outcome.passed:
        finding.confidence = FindingConfidence.CONFIRMED

    return finding


async def run_access_control_and_verify(
    *,
    scan: Scan,
    target_host: str,
    surfaces: list[SurfaceMap],
    personas: list[Persona],
    in_memory_sessions: dict[str, dict],
    http_engine: HttpEngine,
) -> tuple[AccessControlStats, list[Finding], list[TranscriptRecord]]:
    """Runs Phase 6 (steps 1-3) against everything the crawl found, then
    Phase 9 against every candidate it produces. Returns fully-constructed
    Finding/Verification/Evidence objects (relationships set, nothing added
    to any session yet), the TranscriptRecord rows their Evidence needs to
    satisfy the FK (deduped by transcript_id — two boundaries, e.g. vertical
    and horizontal, can legitimately share one candidate's transcript), and
    stats for the phase's ``stats_json``. The caller owns the session, same
    convention as scan_runner's other phase helpers (no session param
    here)."""
    identities = _build_persona_identities(personas, set(in_memory_sessions.keys()))
    personas_by_id = {p.persona_id: p for p in identities}
    observed = _build_observed_requests(surfaces)
    session_for = _build_session_resolver(
        in_memory_sessions=in_memory_sessions, target_host=target_host
    )

    result = await run_access_control(
        http_engine=http_engine,
        observed_requests=observed,
        personas=identities,
        session_for=session_for,
    )

    confirmed = probable = 0
    findings: list[Finding] = []
    transcript_records: dict[str, TranscriptRecord] = {}
    for candidate in result.candidates:
        requesting_identity = personas_by_id[candidate.requesting_persona_id]
        reproduce = _make_reproduce(
            candidate=candidate,
            requesting_identity=requesting_identity,
            http_engine=http_engine,
            session_for=session_for,
        )
        outcome = await verify_candidate(reproduce)
        findings.append(_build_finding(scan=scan, candidate=candidate, outcome=outcome))
        transcript_records.setdefault(
            candidate.denied_transcript_id, _build_transcript_record(scan=scan, candidate=candidate)
        )
        if outcome.passed:
            confirmed += 1
        else:
            probable += 1

    stats = AccessControlStats(
        observed_requests=len(observed),
        candidates_found=len(result.candidates),
        ambiguous_skipped=result.ambiguous_count,
        confirmed=confirmed,
        probable=probable,
    )
    return stats, findings, list(transcript_records.values())
