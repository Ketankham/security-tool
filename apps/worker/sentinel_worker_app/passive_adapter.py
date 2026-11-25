"""Bridges the crawl's SurfaceMaps and the logins' sessions into the passive
checks' plain inputs, runs them, re-runs every candidate through the Phase 9
verification gate, and builds Finding/Evidence/Verification rows (same
"build, don't persist" convention as access_control_adapter.py)."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from urllib.parse import urlsplit

from sentinel_checks.passive import PassiveCandidate, PassiveContext, run_passive_checks
from sentinel_checks.verification import VerificationOutcome, verify_candidate
from sentinel_core.http_engine import HttpEngine
from sentinel_core.scope_guard import ScopeGuard
from sentinel_crawler import SurfaceMap
from sentinel_db.enums import FindingConfidence, FindingSeverity, FindingStatus
from sentinel_db.models import Evidence, Finding, Persona, Scan, TranscriptRecord, Verification

from .scan_log import NULL_LOG, NullScanLog, ScanLog

MAX_ORIGINS = 5
PAGES_PER_ORIGIN = 6
API_URLS_PER_ORIGIN = 8


@dataclass(slots=True)
class PassiveStats:
    requests: int = 0
    candidates: int = 0
    confirmed: int = 0
    probable: int = 0
    per_check: dict[str, int] = field(default_factory=dict)
    failed: dict[str, str] = field(default_factory=dict)
    origins: list[str] = field(default_factory=list)
    # Candidates left out because another step already confirmed the same finding.
    skipped_duplicates: int = 0


def _origin(url: str) -> str:
    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}"


def build_inputs(
    *,
    surfaces: list[SurfaceMap],
    personas: list[Persona],
    in_memory_sessions: dict[str, dict],
    fallback_origin: str,
) -> tuple[list[str], dict[str, list[str]], dict[str, list[str]], dict[str, list[dict]]]:
    """(origins, pages by origin, API URLs by origin, cookies by persona label).

    Origins are the hosts the crawl actually *reached* (the crawler records
    where a visit ended, so an apex that only redirects to www is not one)."""
    origins: list[str] = []
    pages: dict[str, list[str]] = {}
    apis: dict[str, list[str]] = {}

    for surface in surfaces:
        for endpoint in surface.endpoints:
            origin = _origin(endpoint.url)
            if origin not in origins:
                origins.append(origin)
    if not origins:
        origins.append(fallback_origin)
    origins = origins[:MAX_ORIGINS]

    # Pages come from the logged-out crawl only: what any visitor can load.
    for surface in surfaces:
        for endpoint in surface.endpoints:
            origin = _origin(endpoint.url)
            if origin not in origins or endpoint.method != "GET":
                continue
            if endpoint.source == "network":
                bucket = apis.setdefault(origin, [])
                if endpoint.url not in bucket and len(bucket) < API_URLS_PER_ORIGIN:
                    bucket.append(endpoint.url)
            elif endpoint.source == "link" and surface.persona_id == "anonymous":
                bucket = pages.setdefault(origin, [])
                if endpoint.url not in bucket and len(bucket) < PAGES_PER_ORIGIN:
                    bucket.append(endpoint.url)
    for urls in pages.values():
        # The site's front page is the most representative sample.
        urls.sort(key=lambda u: urlsplit(u).path not in ("", "/"))

    cookies: dict[str, list[dict]] = {}
    for persona in personas:
        state = in_memory_sessions.get(str(persona.id))
        if not state:
            continue
        # Flags and names only: values never leave the session.
        cookies[persona.label] = [
            {k: c.get(k) for k in ("name", "domain", "secure", "httpOnly", "sameSite")}
            for c in state.get("cookies", [])
        ]
    return origins, pages, apis, cookies


def candidate_fingerprint(candidate: PassiveCandidate) -> str:
    """The stable identity of what a candidate reports (rule, host, subject):
    the same value ``build_finding`` stores, so two steps that find the same
    thing can recognise it without building the Finding first."""
    return Finding.compute_fingerprint(
        rule_id=candidate.rule_id,
        endpoint_template=candidate.origin,
        param=candidate.subject,
        persona_pair="",
    )


def build_finding(
    *, scan: Scan, candidate: PassiveCandidate, outcome: VerificationOutcome | None
) -> Finding:
    """A Finding (with Evidence and, when ``outcome`` is given, a Verification)
    for a passive-style candidate. CONFIRMED only when the outcome passed;
    shared by the passive checks and the directory brute force step."""
    first = candidate.evidence[0] if candidate.evidence else None
    finding = Finding(
        scan_id=scan.id,
        fingerprint=candidate_fingerprint(candidate),
        rule_id=candidate.rule_id,
        title=candidate.title[:300],
        cwe=candidate.cwe,
        owasp_top10=candidate.owasp,
        severity=FindingSeverity(candidate.severity),
        confidence=FindingConfidence.PROBABLE,
        status=FindingStatus.OPEN,
        reproduction={
            "method": first.method if first else "GET",
            "url": first.url if first else candidate.origin,
            "curl": candidate.reproduction_curl,
            "expect": candidate.reproduction_expect,
        },
        narrative=candidate.narrative[:10_000],
        remediation={
            "summary": candidate.remediation_summary,
            "steps": candidate.remediation_steps,
        },
        first_seen_scan_id=scan.id,
        last_seen_scan_id=scan.id,
    )
    if outcome is not None:
        # Via the relationship so the before_flush invariant (CONFIRMED needs a
        # passed Verification) sees it on the Python object.
        finding.verification = Verification(
            reproduced_count=outcome.reproduced_count,
            attempted_count=outcome.attempted_count,
            passed=outcome.passed,
            last_run_at=datetime.now(UTC),
            details={"how": "the same probe was re-run independently"},
        )
        if outcome.passed:
            finding.confidence = FindingConfidence.CONFIRMED
    for ref in candidate.evidence:
        finding.evidence.append(
            Evidence(transcript_id=ref.transcript_id, role=ref.role, note=ref.note[:1000])
        )
    return finding


async def run_passive_and_verify(
    *,
    scan: Scan,
    fallback_origin: str,
    surfaces: list[SurfaceMap],
    personas: list[Persona],
    in_memory_sessions: dict[str, dict],
    http_engine: HttpEngine,
    scope_guard: ScopeGuard,
    log: ScanLog | NullScanLog = NULL_LOG,
    skip_fingerprints: set[str] | None = None,
) -> tuple[PassiveStats, list[Finding], list[TranscriptRecord]]:
    """``skip_fingerprints``: findings another step of this scan already
    confirmed (directory brute force: an exposed .env it re-checked twice).
    A passive candidate with one of these fingerprints is not reported again."""
    origins, pages, apis, cookies = build_inputs(
        surfaces=surfaces,
        personas=personas,
        in_memory_sessions=in_memory_sessions,
        fallback_origin=fallback_origin,
    )
    log.add(
        "passive_checks",
        f"Checking {len(origins)} host(s) for security headers, cookie flags, CORS, exposed "
        f"files and TLS: {', '.join(origins)}. Read-only requests, within the scan's scope "
        "and speed limit.",
    )

    ctx = PassiveContext(
        http=http_engine,
        origins=origins,
        pages_by_origin=pages,
        api_urls_by_origin=apis,
        persona_cookies=cookies,
        log=lambda level, message: log.add("passive_checks", message, level=level),
        scope_allows=lambda url: scope_guard.evaluate(method="GET", url=url).allowed,
    )
    result = await run_passive_checks(ctx)

    stats = PassiveStats(
        requests=result.requests,
        per_check=dict(result.per_check),
        failed=dict(result.failed),
        origins=origins,
    )
    findings: list[Finding] = []
    records: dict[str, TranscriptRecord] = {}
    skip = skip_fingerprints or set()
    for candidate in result.candidates:
        if skip and candidate_fingerprint(candidate) in skip:
            stats.skipped_duplicates += 1
            log.add(
                "passive_checks",
                f"Skipped {candidate.title}: already confirmed by directory brute force.",
            )
            continue
        outcome: VerificationOutcome | None = None
        if candidate.reproduce is not None:
            try:
                outcome = await verify_candidate(candidate.reproduce)
            except Exception as exc:  # noqa: BLE001 — a failed re-check leaves it "probable"
                log.add(
                    "passive_checks",
                    f"Could not re-check {candidate.rule_id} ({candidate.origin}): {exc}",
                    level="warn",
                )
        finding = build_finding(scan=scan, candidate=candidate, outcome=outcome)
        findings.append(finding)
        for ref in candidate.evidence:
            records.setdefault(
                ref.transcript_id,
                TranscriptRecord(
                    transcript_id=ref.transcript_id,
                    scan_id=scan.id,
                    persona_id=None,
                    method=ref.method,
                    url=ref.url[:2000],
                    status_code=ref.status_code,
                ),
            )
        confirmed = finding.confidence is FindingConfidence.CONFIRMED
        stats.confirmed += int(confirmed)
        stats.probable += int(not confirmed)
        log.add(
            "passive_checks",
            f"Finding [{candidate.severity}, {'confirmed' if confirmed else 'probable'}]: "
            f"{candidate.title}",
            level="warn" if candidate.severity in ("critical", "high") else "info",
        )
    stats.candidates = len(findings)
    log.add(
        "passive_checks",
        f"Passive checks done: {stats.requests} request(s), {stats.candidates} finding(s) "
        f"({stats.confirmed} confirmed by re-checking, {stats.probable} probable).",
    )
    return stats, findings, list(records.values())
