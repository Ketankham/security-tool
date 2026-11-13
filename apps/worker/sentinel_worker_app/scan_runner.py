"""The scan orchestrator: walks sentinel_core.state_machine.ScanStateMachine
through the phases this milestone actually implements, persisting progress
after every step so a crashed worker resumes rather than restarts
(docs/01-architecture.md §5).

M1 scope (docs/05-v1-roadmap.md): SCOPE_VERIFYING, RECON, AUTH_ESTABLISHING,
CRAWLING, and SURFACE_MAPPING.

M2 scope (this milestone): of the parallel TESTING phases, only
ACCESS_CONTROL is real — the authorization engine's three boundaries
(vertical/horizontal/anonymous, docs/03 §4.1) plus the Phase 9 verification
gate. ACTIVE_INJECTION, SESSION_CHECKS, and BUSINESS_LOGIC are marked
SKIPPED (M3, M2-follow-up, and v1.5 respectively). PASSIVE_CHECKS is also
SKIPPED (M3 breadth). TRIAGING is minimal (fingerprint assignment only — no
cross-scan dedup/regression detection or CVSS/clustering yet). REPORTING
produces a ScanReport (recon/surface/findings summary — see
sentinel_reporter) scoped to what actually ran; PDF, SARIF, the AI-written
narrative, and the attestation letter are M3/Verified-tier work.

A scan that reaches here genuinely completes (ScanState.COMPLETE) —
whatever it found (or honestly didn't check yet, per its own
degraded_reasons and the report's scope_note) rather than claiming a scan
that never ran a single check (docs/04-edge-cases.md §G's spirit, now
satisfied by finishing instead of pausing).
"""

from __future__ import annotations

import json
import re
import uuid
from datetime import UTC, datetime

import structlog
from playwright.async_api import Browser, async_playwright
from redis.asyncio import Redis
from sentinel_auth.browser import chromium_launch_kwargs
from sentinel_core import scan_options as scan_options_mod
from sentinel_core.crypto import EnvelopeCrypto, LocalMasterKeyProvider
from sentinel_core.rate_limiter import RateLimiter
from sentinel_core.state_machine import (
    TERMINAL_STATES,
    PhaseStatus,
    ScanPhaseName,
    ScanState,
    ScanStateMachine,
)
from sentinel_crawler import PersonaCrawler, SurfaceMap
from sentinel_db import open_session
from sentinel_db.models import (
    Asset,
    Finding,
    Organization,
    Persona,
    Scan,
    ScanPhase,
    ScopeRule,
    Target,
    TranscriptRecord,
)
from sentinel_recon import run_recon
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from .access_control_adapter import AccessControlStats, run_access_control_and_verify
from .auth_adapter import establish_persona
from .config import Settings, get_settings
from .report_adapter import build_scan_report, persist_report
from .substrate import build_http_engine, build_report_store, build_scope_guard
from .surface_adapter import merge_surface_map

log = structlog.get_logger(__name__)

SKIPPED_PASSIVE_CHECKS_NOTE = (
    "Passive/config checks (headers, cookies, CORS, TLS, nuclei) are not "
    "implemented yet — M3 breadth work (docs/05-v1-roadmap.md)."
)
SKIPPED_ACTIVE_INJECTION_NOTE = (
    "Active injection testing (XSS, SQLi, SSTI, SSRF, ...) is not "
    "implemented yet — M3 (docs/05-v1-roadmap.md)."
)
SKIPPED_SESSION_CHECKS_NOTE = (
    "Session-management checks (logout invalidation, JWT, CSRF, ...) are "
    "not implemented yet — an M2 follow-up slice (docs/03-check-catalogue.md "
    "§5)."
)
SKIPPED_BUSINESS_LOGIC_NOTE = (
    "Business-logic testing is deliberately out of v1 scope — human/"
    "Verified-tier only (docs/05-v1-roadmap.md)."
)


async def _get_or_create_phase(session: AsyncSession, scan: Scan, name: ScanPhaseName) -> ScanPhase:
    for phase in scan.phases:
        if phase.name == name:
            return phase
    phase = ScanPhase(scan_id=scan.id, name=name)
    session.add(phase)
    scan.phases.append(phase)
    await session.flush()
    return phase


async def _start_phase(session: AsyncSession, phase: ScanPhase) -> None:
    phase.status = PhaseStatus.RUNNING
    phase.started_at = datetime.now(UTC)
    await session.flush()


async def _finish_phase(
    session: AsyncSession,
    phase: ScanPhase,
    *,
    status: PhaseStatus,
    stats: dict,
    error: str | None = None,
) -> None:
    phase.status = status
    phase.finished_at = datetime.now(UTC)
    phase.stats_json = stats
    phase.error = error
    await session.flush()


async def _run_auth_establishing(
    *,
    scan: Scan,
    target: Target,
    org: Organization,
    scope_rules: list[ScopeRule],
    configured_personas: list[Persona],
    settings: Settings,
    redis_client: Redis,
    browser: Browser,
    oracle_probe_url: str | None = None,
) -> tuple[dict, dict[str, dict]]:
    """Returns (stats, {persona_id: storage_state}) for personas that became
    available this run. Never raises for an individual persona's login
    failure — that's recorded on the persona row and in stats instead.

    ``oracle_probe_url`` defaults to the target's own root URL; tests pass
    an explicit one (a real local fixture's URL, http:// and a real port)
    since Playwright/HttpEngine resolve `target.root_domain` through real
    DNS/TLS and have no notion of a docker-compose-style port mapping —
    see tests/benchmark/README.md for the same gap in recon.
    """
    auth_stats: dict = {
        "personas_configured": len(configured_personas),
        "personas_available": 0,
        # persona id -> the page its login landed on; seeds that persona's
        # crawl (QA #37: a crawl from the home page alone found 1 page).
        "landing_pages": {},
    }
    in_memory_sessions: dict[str, dict] = {}

    if not configured_personas:
        return auth_stats, in_memory_sessions

    crypto = EnvelopeCrypto(LocalMasterKeyProvider([settings.kms_master_key.encode()]))
    org_data_key = crypto.unwrap_data_key(org.wrapped_data_key)
    scope_guard = build_scope_guard(target, scope_rules)
    engine = build_http_engine(
        scope_guard=scope_guard,
        redis_client=redis_client,
        settings=settings,
        target_id=str(target.id),
        scan_id=str(scan.id),
        requests_per_second=scan_options_mod.resolve(scan.options)[0],
    )
    probe_url = oracle_probe_url or f"https://{target.root_domain}/"  # fallback probe

    try:
        for persona in configured_personas:
            try:
                result = await establish_persona(
                    persona=persona,
                    browser=browser,
                    crypto=crypto,
                    org_data_key=org_data_key,
                    engine=engine,
                    oracle_probe_url=probe_url,
                    target_root_domain=target.root_domain,
                )
            except Exception as exc:  # noqa: BLE001 — one persona must never end the scan
                log.error(
                    "scan_runner.persona_auth_crashed", persona_id=str(persona.id), exc_info=True
                )
                persona.is_available = False
                persona.unavailable_reason = (
                    f"Login crashed: {type(exc).__name__}: {str(exc).splitlines()[0][:300]}"
                    if str(exc)
                    else f"Login crashed: {type(exc).__name__}"
                )
                continue
            persona.is_available = result.available
            persona.unavailable_reason = result.unavailable_reason
            if not result.available:
                continue

            auth_stats["personas_available"] += 1
            if result.final_url:
                auth_stats["landing_pages"][str(persona.id)] = result.final_url
            in_memory_sessions[str(persona.id)] = result.storage_state or {}
            persona.session_state_ciphertext = crypto.encrypt(
                org_data_key, json.dumps(result.storage_state).encode()
            )
            persona.session_state_updated_at = datetime.now(UTC)
            persona.session_oracle = (
                {
                    "probe_method": result.session_oracle.probe_method,
                    "probe_url": result.session_oracle.probe_url,
                    "signal": result.session_oracle.signal,
                    "authenticated_value": result.session_oracle.authenticated_value,
                }
                if result.session_oracle
                else None
            )
            if result.session_oracle is None:
                scan.is_degraded = True
                scan.degraded_reasons = [
                    *scan.degraded_reasons,
                    f"Persona '{persona.label}': {result.oracle_detail}",
                ]
    finally:
        await engine.aclose()

    return auth_stats, in_memory_sessions


async def _run_crawling(
    *,
    target: Target,
    scope_rules: list[ScopeRule],
    configured_personas: list[Persona],
    in_memory_sessions: dict[str, dict],
    redis_client: Redis,
    browser: Browser,
    root_url: str | None = None,
    landing_pages: dict[str, str] | None = None,
    options: dict | None = None,
) -> list[SurfaceMap]:
    """``root_url`` defaults to the target's own root URL; tests pass an
    explicit one — see _run_auth_establishing's docstring for why."""
    scope_guard = build_scope_guard(target, scope_rules)
    requests_per_second, max_pages = scan_options_mod.resolve(options)
    rate_limiter = RateLimiter(redis_client, default_rate_per_sec=requests_per_second)
    crawler = PersonaCrawler(
        scope_guard=scope_guard,
        rate_limiter=rate_limiter,
        target_id=str(target.id),
        max_pages=max_pages,
    )
    effective_root_url = root_url or f"https://{target.root_domain}/"

    landing_pages = landing_pages or {}
    # The anonymous visitor also starts from each login page and each
    # persona's landing page: what a logged-out visitor gets there is part
    # of the surface (and of the logged-in vs logged-out comparison).
    anon_seeds = [
        *(p.login_recipe.get("start_url") for p in configured_personas if p.login_recipe),
        *landing_pages.values(),
    ]
    surfaces: list[SurfaceMap] = [
        await crawler.crawl(
            browser,
            root_url=effective_root_url,
            persona_id="anonymous",
            seeds=[u for u in anon_seeds if u],
        )
    ]
    for persona in configured_personas:
        storage_state = in_memory_sessions.get(str(persona.id))
        if storage_state is None:
            continue  # this persona never became available this run
        surfaces.append(
            await crawler.crawl(
                browser,
                root_url=effective_root_url,
                persona_id=str(persona.id),
                storage_state=storage_state,
                seeds=[landing_pages[str(persona.id)]]
                if str(persona.id) in landing_pages
                else None,
            )
        )
    return surfaces


async def _run_access_control(
    *,
    scan: Scan,
    target: Target,
    scope_rules: list[ScopeRule],
    surfaces: list[SurfaceMap],
    personas: list[Persona],
    in_memory_sessions: dict[str, dict],
    settings: Settings,
    redis_client: Redis,
    target_host: str | None = None,
) -> tuple[AccessControlStats, list[Finding], list[TranscriptRecord]]:
    """``target_host`` defaults to the target's own root domain; tests pass
    an explicit one — see _run_auth_establishing's docstring for why."""
    scope_guard = build_scope_guard(target, scope_rules)
    engine = build_http_engine(
        scope_guard=scope_guard,
        redis_client=redis_client,
        settings=settings,
        target_id=str(target.id),
        scan_id=str(scan.id),
        requests_per_second=scan_options_mod.resolve(scan.options)[0],
    )
    try:
        return await run_access_control_and_verify(
            scan=scan,
            target_host=target_host or target.root_domain,
            surfaces=surfaces,
            personas=personas,
            in_memory_sessions=in_memory_sessions,
            http_engine=engine,
        )
    finally:
        await engine.aclose()


async def _first_invalid_regex_rule(
    session: AsyncSession, target_id: uuid.UUID
) -> ScopeRule | None:
    result = await session.execute(
        select(ScopeRule).where(ScopeRule.target_id == target_id, ScopeRule.kind == "path_regex")
    )
    for rule in result.scalars():
        try:
            re.compile(rule.pattern)
        except re.error:
            return rule
    return None


async def run_scan(scan_id: str) -> None:
    async with open_session() as session:
        # `selectinload` here matters, not just for speed: AsyncSession
        # forbids implicit lazy I/O on plain attribute access (`scan.phases`
        # below, in _get_or_create_phase) outside its own internal greenlet
        # context — the same MissingGreenlet trap the API hit (see
        # apps/api/sentinel_api_app/routers/scans.py). Eager-load it up front.
        scan = await session.get(Scan, uuid.UUID(scan_id), options=[selectinload(Scan.phases)])
        if scan is None:
            log.warning("scan_runner.scan_not_found", scan_id=scan_id)
            return

        target = await session.get(Target, scan.target_id)
        if target is None:
            log.error(
                "scan_runner.target_not_found", scan_id=scan_id, target_id=str(scan.target_id)
            )
            return

        machine = ScanStateMachine(current=scan.state, paused_from=scan.paused_from)

        # --- Phase: SCOPE_VERIFYING ---
        phase = await _get_or_create_phase(session, scan, ScanPhaseName.SCOPE_VERIFYING)
        machine.transition(ScanState.SCOPE_VERIFYING)
        scan.state = machine.current
        scan.started_at = scan.started_at or datetime.now(UTC)
        await _start_phase(session, phase)

        if get_settings().require_ownership_verification and not target.is_scannable:
            machine.transition(ScanState.BLOCKED_UNVERIFIED)
            scan.state = machine.current
            await _finish_phase(
                session,
                phase,
                status=PhaseStatus.FAILED,
                stats={},
                error="Target is not scannable (ownership/authorization gate failed).",
            )
            scan.finished_at = datetime.now(UTC)
            await session.commit()
            log.info("scan_runner.blocked_unverified", scan_id=scan_id)
            return

        # Rules saved before the API validated them (QA #11 saved "([") would
        # raise inside the ScopeGuard mid-scan. Silently skipping one would
        # be worse: a broken *exclude* rule would widen the scope. So stop
        # here, before any request, and say which rule to fix.
        bad_rule = await _first_invalid_regex_rule(session, target.id)
        if bad_rule is not None:
            machine.transition(ScanState.BLOCKED_UNVERIFIED)
            scan.state = machine.current
            await _finish_phase(
                session,
                phase,
                status=PhaseStatus.FAILED,
                stats={},
                error=(
                    f"Scope rule '{bad_rule.pattern}' ({bad_rule.effect} path_regex) is not a "
                    "valid regular expression. Fix or delete it on the target page, then rerun."
                ),
            )
            scan.finished_at = datetime.now(UTC)
            await session.commit()
            log.info("scan_runner.invalid_scope_rule", scan_id=scan_id, rule_id=str(bad_rule.id))
            return

        await _finish_phase(
            session, phase, status=PhaseStatus.COMPLETED, stats={"target_scannable": True}
        )
        await session.commit()

        # --- Phase: RECON ---
        phase = await _get_or_create_phase(session, scan, ScanPhaseName.RECON)
        machine.transition(ScanState.RECON)
        scan.state = machine.current
        await _start_phase(session, phase)
        await session.commit()

        recon_result = await run_recon(target.root_domain)

        for asset in recon_result.assets:
            session.add(
                Asset(
                    scan_id=scan.id,
                    host=asset.host,
                    ip_addresses=asset.ips,
                    http_probes=[
                        {
                            "url": p.url,
                            "status_code": p.status_code,
                            "title": p.title,
                            "server": p.server,
                            "tech": p.tech,
                            "error": p.error,
                        }
                        for p in asset.http_probes
                    ],
                    discovery_source=asset.source,
                )
            )

        await _finish_phase(
            session,
            phase,
            status=PhaseStatus.COMPLETED,
            stats={
                "assets_found": len(recon_result.assets),
                "tool_availability": recon_result.tool_availability,
                "wildcard_dns_suspected": recon_result.wildcard_dns_suspected,
                "notes": recon_result.notes,
            },
        )
        if recon_result.degraded:
            scan.is_degraded = True
            scan.degraded_reasons = [*scan.degraded_reasons, *recon_result.notes]
        await session.commit()

        # --- Shared setup for AUTH_ESTABLISHING + CRAWLING ---
        settings = get_settings()
        org = await session.get(Organization, target.organization_id)
        scope_rules = list(
            (await session.execute(select(ScopeRule).where(ScopeRule.target_id == target.id)))
            .scalars()
            .all()
        )
        personas = list(
            (
                await session.execute(
                    select(Persona)
                    .where(Persona.target_id == target.id)
                    .options(selectinload(Persona.credential))
                )
            )
            .scalars()
            .all()
        )
        configured_personas = [p for p in personas if p.login_recipe]

        # --- Phase: AUTH_ESTABLISHING ---
        phase = await _get_or_create_phase(session, scan, ScanPhaseName.AUTH_ESTABLISHING)
        machine.transition(ScanState.AUTH_ESTABLISHING)
        scan.state = machine.current
        await _start_phase(session, phase)
        await session.commit()

        in_memory_sessions: dict[str, dict] = {}
        landing_pages: dict[str, str] = {}

        if not settings.kms_master_key and configured_personas:
            note = (
                "KMS_MASTER_KEY is not configured — cannot decrypt any persona "
                "credentials. Proceeding with an anonymous-only crawl."
            )
            scan.is_degraded = True
            scan.degraded_reasons = [*scan.degraded_reasons, note]
            await _finish_phase(session, phase, status=PhaseStatus.SKIPPED, stats={"error": note})
        elif not configured_personas:
            note = (
                "No personas have a login recipe configured — "
                "proceeding with an anonymous-only crawl."
            )
            scan.is_degraded = True
            scan.degraded_reasons = [*scan.degraded_reasons, note]
            await _finish_phase(
                session,
                phase,
                status=PhaseStatus.COMPLETED,
                stats={"personas_configured": 0, "personas_available": 0},
            )
        else:
            redis_client: Redis = Redis.from_url(settings.redis_url)
            try:
                async with async_playwright() as pw:
                    browser = await pw.chromium.launch(**chromium_launch_kwargs())
                    try:
                        auth_stats, in_memory_sessions = await _run_auth_establishing(
                            scan=scan,
                            target=target,
                            org=org,
                            scope_rules=scope_rules,
                            configured_personas=configured_personas,
                            settings=settings,
                            redis_client=redis_client,
                            browser=browser,
                        )
                    finally:
                        await browser.close()
            finally:
                await redis_client.aclose()

            landing_pages = auth_stats.get("landing_pages", {})
            failed = [p for p in configured_personas if not p.is_available]
            for persona in failed:
                scan.is_degraded = True
                scan.degraded_reasons = [
                    *scan.degraded_reasons,
                    f"Login for '{persona.label}' failed, so that role was not tested: "
                    f"{persona.unavailable_reason}",
                ]

            if auth_stats["personas_available"] == 0:
                # v1: a broken login must not throw away the rest of the
                # scan (recon, the anonymous crawl, and checks that need no
                # login still have value). Record it loudly and carry on as
                # an anonymous visitor; the persona rows and the notes above
                # say exactly which login failed and why.
                scan.is_degraded = True
                scan.degraded_reasons = [
                    *scan.degraded_reasons,
                    "No login worked, so the scan continued as an anonymous visitor only: "
                    "checks that compare what different users can reach were skipped. "
                    "Fix the login (use Test login on the target page), then retry the scan.",
                ]
                await _finish_phase(
                    session,
                    phase,
                    status=PhaseStatus.FAILED,
                    stats=auth_stats,
                    error="All configured logins failed; continuing anonymously.",
                )
                log.info("scan_runner.all_logins_failed_continuing", scan_id=scan_id)
            else:
                await _finish_phase(session, phase, status=PhaseStatus.COMPLETED, stats=auth_stats)

        machine.transition(ScanState.CRAWLING)
        scan.state = machine.current
        await session.commit()

        # --- Phase: CRAWLING ---
        phase = await _get_or_create_phase(session, scan, ScanPhaseName.CRAWLING)
        await _start_phase(session, phase)
        await session.commit()

        redis_client = Redis.from_url(settings.redis_url)
        try:
            async with async_playwright() as pw:
                browser = await pw.chromium.launch(**chromium_launch_kwargs())
                try:
                    surfaces = await _run_crawling(
                        target=target,
                        scope_rules=scope_rules,
                        configured_personas=configured_personas,
                        in_memory_sessions=in_memory_sessions,
                        redis_client=redis_client,
                        browser=browser,
                        landing_pages=landing_pages,
                        options=scan.options,
                    )
                finally:
                    await browser.close()
        finally:
            await redis_client.aclose()

        await _finish_phase(
            session,
            phase,
            status=PhaseStatus.COMPLETED,
            stats={
                "personas_crawled": [s.persona_id for s in surfaces],
                "pages_visited_by_persona": {s.persona_id: s.pages_visited for s in surfaces},
                "endpoints_by_persona": {s.persona_id: len(s.endpoints) for s in surfaces},
            },
        )
        machine.transition(ScanState.SURFACE_MAPPING)
        scan.state = machine.current
        await session.commit()

        # --- Phase: SURFACE_MAPPING ---
        phase = await _get_or_create_phase(session, scan, ScanPhaseName.SURFACE_MAPPING)
        await _start_phase(session, phase)
        await session.commit()

        total_created = total_merged = total_assets = 0
        for surface in surfaces:
            merge_stats = await merge_surface_map(session, scan_id=scan.id, surface=surface)
            total_created += merge_stats.endpoints_created
            total_merged += merge_stats.endpoints_merged
            total_assets += merge_stats.assets_created

        await _finish_phase(
            session,
            phase,
            status=PhaseStatus.COMPLETED,
            stats={
                "endpoints_created": total_created,
                "endpoints_merged_across_personas": total_merged,
                "assets_created": total_assets,
            },
        )
        await session.commit()

        # --- Phase: PASSIVE_CHECKS (SKIPPED — M3 breadth work) ---
        phase = await _get_or_create_phase(session, scan, ScanPhaseName.PASSIVE_CHECKS)
        machine.transition(ScanState.PASSIVE_CHECKS)
        scan.state = machine.current
        await _start_phase(session, phase)
        scan.is_degraded = True
        scan.degraded_reasons = [*scan.degraded_reasons, SKIPPED_PASSIVE_CHECKS_NOTE]
        await _finish_phase(session, phase, status=PhaseStatus.SKIPPED, stats={})

        machine.transition(ScanState.TESTING)
        scan.state = machine.current
        await session.commit()

        # --- Phase: ACCESS_CONTROL (the moat — docs/03 §4) ---
        phase = await _get_or_create_phase(session, scan, ScanPhaseName.ACCESS_CONTROL)
        await _start_phase(session, phase)
        await session.commit()

        redis_client = Redis.from_url(settings.redis_url)
        try:
            access_control_stats, findings, transcript_records = await _run_access_control(
                scan=scan,
                target=target,
                scope_rules=scope_rules,
                surfaces=surfaces,
                personas=personas,
                in_memory_sessions=in_memory_sessions,
                settings=settings,
                redis_client=redis_client,
            )
        finally:
            await redis_client.aclose()

        # transcript_records first: Evidence.transcript_id has a real FK to
        # them (SQLAlchemy sorts inserts by dependency at flush time
        # regardless, but this is the actual order the FK requires).
        session.add_all(transcript_records)
        session.add_all(findings)
        await session.flush()

        await _finish_phase(
            session,
            phase,
            status=PhaseStatus.COMPLETED,
            stats={
                "observed_requests": access_control_stats.observed_requests,
                "candidates_found": access_control_stats.candidates_found,
                "ambiguous_skipped": access_control_stats.ambiguous_skipped,
                "confirmed": access_control_stats.confirmed,
                "probable": access_control_stats.probable,
            },
        )
        if access_control_stats.ambiguous_skipped:
            scan.is_degraded = True
            scan.degraded_reasons = [
                *scan.degraded_reasons,
                f"{access_control_stats.ambiguous_skipped} access-control diff(s) could not be "
                "confidently judged (Layer 4 LLM adjudication is not implemented yet) and were "
                "not reported as findings.",
            ]

        # --- Phases: ACTIVE_INJECTION, SESSION_CHECKS, BUSINESS_LOGIC (SKIPPED) ---
        for phase_name, note in (
            (ScanPhaseName.ACTIVE_INJECTION, SKIPPED_ACTIVE_INJECTION_NOTE),
            (ScanPhaseName.SESSION_CHECKS, SKIPPED_SESSION_CHECKS_NOTE),
            (ScanPhaseName.BUSINESS_LOGIC, SKIPPED_BUSINESS_LOGIC_NOTE),
        ):
            phase = await _get_or_create_phase(session, scan, phase_name)
            await _start_phase(session, phase)
            await _finish_phase(session, phase, status=PhaseStatus.SKIPPED, stats={})
            scan.is_degraded = True
            scan.degraded_reasons = [*scan.degraded_reasons, note]
        await session.commit()

        # --- Phase: VERIFYING ---
        # Verification already ran candidate-by-candidate inside
        # _run_access_control (Phase 9 is check-agnostic, and each check
        # engine runs it against its own candidates as it produces them —
        # docs/02 Phase 9). This phase records that it happened.
        phase = await _get_or_create_phase(session, scan, ScanPhaseName.VERIFYING)
        machine.transition(ScanState.VERIFYING)
        scan.state = machine.current
        await _start_phase(session, phase)
        await _finish_phase(
            session,
            phase,
            status=PhaseStatus.COMPLETED,
            stats={
                "candidates_verified": access_control_stats.candidates_found,
                "confirmed": access_control_stats.confirmed,
                "probable": access_control_stats.probable,
            },
        )
        await session.commit()

        # --- Phase: TRIAGING (minimal — fingerprinting only) ---
        # Cross-scan dedup/regression detection (FindingStatus transitions
        # to FIXED/REGRESSED) and CVSS/clustering are not implemented yet —
        # every finding's fingerprint is assigned (docs/01 §6.6) so a future
        # slice can add that lookup without a data migration.
        phase = await _get_or_create_phase(session, scan, ScanPhaseName.TRIAGING)
        machine.transition(ScanState.TRIAGING)
        scan.state = machine.current
        await _start_phase(session, phase)
        await _finish_phase(
            session,
            phase,
            status=PhaseStatus.COMPLETED,
            stats={"findings_triaged": len(findings)},
        )
        await session.commit()

        # --- Phase: REPORTING ---
        # Scoped to what actually ran (docs/05-v1-roadmap.md M2 slice 2): a
        # recon/surface/findings summary. PDF, SARIF, the AI-written
        # narrative, and the attestation letter are M3/Verified-tier work —
        # ScanReport.to_dict()'s own scope_note says so in the artifact
        # itself, not just here.
        phase = await _get_or_create_phase(session, scan, ScanPhaseName.REPORTING)
        machine.transition(ScanState.REPORTING)
        scan.state = machine.current
        await _start_phase(session, phase)

        report = await build_scan_report(
            session,
            scan=scan,
            target=target,
            personas_crawled=[s.persona_id for s in surfaces],
        )
        report_row = await persist_report(report, scan=scan, store=build_report_store(settings))
        session.add(report_row)
        await session.flush()

        await _finish_phase(
            session,
            phase,
            status=PhaseStatus.COMPLETED,
            stats={"report_id": str(report_row.id), **report.summary},
        )

        machine.transition(ScanState.COMPLETE)
        scan.state = machine.current
        scan.finished_at = datetime.now(UTC)
        await session.commit()

        log.info(
            "scan_runner.completed",
            scan_id=scan_id,
            assets_found=len(recon_result.assets),
            personas_crawled=len(surfaces),
            endpoints_created=total_created,
            findings_confirmed=access_control_stats.confirmed,
            findings_probable=access_control_stats.probable,
            report_id=str(report_row.id),
        )


# --- Failure handling (v1: "a scan never stays stuck") ------------------------

# States a scan is in only while a worker is actively running it.
_IN_PROGRESS_STATES = frozenset(
    s
    for s in ScanState
    if s not in TERMINAL_STATES and s not in (ScanState.QUEUED, ScanState.PAUSED)
)


def _close_scan_as_failed(scan: Scan, reason: str) -> None:
    """Terminal FAILED with a readable reason; any phase left RUNNING is
    closed as FAILED with the same reason so the dashboard shows where it
    stopped."""
    now = datetime.now(UTC)
    scan.state = ScanState.FAILED
    scan.fail_reason = reason[:1000]
    scan.finished_at = now
    for phase in scan.phases:
        if phase.status is PhaseStatus.RUNNING:
            phase.status = PhaseStatus.FAILED
            phase.finished_at = now
            phase.error = reason[:2000]


async def mark_scan_failed(scan_id: str, reason: str) -> bool:
    """Called by the Celery task when run_scan raised. Returns False when
    the scan is missing or already terminal (nothing to do)."""
    async with open_session() as session:
        scan = await session.get(Scan, uuid.UUID(scan_id), options=[selectinload(Scan.phases)])
        if scan is None or scan.state in TERMINAL_STATES:
            return False
        running = next((p.name.value for p in scan.phases if p.status is PhaseStatus.RUNNING), None)
        where = f" during {running.replace('_', ' ')}" if running else ""
        _close_scan_as_failed(scan, f"The scan stopped{where}: {reason}")
        await session.commit()
        log.info("scan_runner.marked_failed", scan_id=scan_id, phase=running)
        return True


async def fail_interrupted_scans() -> int:
    """Run once when the scan worker starts. The deployment runs exactly one
    scan worker with concurrency 1, so at start-up nothing can legitimately
    be mid-scan: any scan still in a running state was cut off by a crash,
    an out-of-memory kill or a deploy, and Celery will not hand it out
    again. Without this it would show "Crawling…" forever."""
    async with open_session() as session:
        result = await session.execute(
            select(Scan)
            .where(Scan.state.in_(list(_IN_PROGRESS_STATES)))
            .options(selectinload(Scan.phases))
        )
        scans = list(result.scalars().all())
        for scan in scans:
            _close_scan_as_failed(
                scan,
                "The scan was interrupted: the scan worker restarted while it was running "
                "(a deploy, a crash or running out of memory). Use Retry to run it again.",
            )
        await session.commit()
        if scans:
            log.warning("scan_runner.failed_interrupted_scans", count=len(scans))
        return len(scans)
