"""The scan orchestrator: walks sentinel_core.state_machine.ScanStateMachine
through the phases this milestone actually implements, persisting progress
after every step so a crashed worker resumes rather than restarts
(docs/01-architecture.md §5).

M1 scope (docs/05-v1-roadmap.md): SCOPE_VERIFYING, RECON, AUTH_ESTABLISHING,
CRAWLING, and SURFACE_MAPPING are real. Every phase after that — the
parallel TESTING phases (injection/authz/session/business-logic), verify,
triage, report — is not implemented yet, so this orchestrator stops there,
honestly: it transitions the scan to PAUSED (not COMPLETE, and not a fake
success) with a clear degraded_reasons note, rather than claiming a
finished scan that never ran a single check (docs/04-edge-cases.md §G).
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime

import structlog
from playwright.async_api import Browser, async_playwright
from redis.asyncio import Redis
from sentinel_auth.browser import chromium_launch_kwargs
from sentinel_core.crypto import EnvelopeCrypto, LocalMasterKeyProvider
from sentinel_core.rate_limiter import RateLimiter
from sentinel_core.state_machine import PhaseStatus, ScanPhaseName, ScanState, ScanStateMachine
from sentinel_crawler import PersonaCrawler, SurfaceMap
from sentinel_db import open_session
from sentinel_db.models import Asset, Organization, Persona, Scan, ScanPhase, ScopeRule, Target
from sentinel_recon import run_recon
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from .auth_adapter import establish_persona
from .config import Settings, get_settings
from .substrate import build_http_engine, build_scope_guard
from .surface_adapter import merge_surface_map

log = structlog.get_logger(__name__)

NOT_YET_IMPLEMENTED_NOTE = (
    "Paused after surface mapping — the check engines (injection, authz, "
    "session, business-logic) and everything past them are not implemented "
    "yet (see docs/05-v1-roadmap.md milestones M2-M3). This scan can be "
    "resumed once they land; it is not stuck or broken."
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
    auth_stats: dict = {"personas_configured": len(configured_personas), "personas_available": 0}
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
    )
    probe_url = oracle_probe_url or f"https://{target.root_domain}/"

    try:
        for persona in configured_personas:
            result = await establish_persona(
                persona=persona,
                browser=browser,
                crypto=crypto,
                org_data_key=org_data_key,
                engine=engine,
                oracle_probe_url=probe_url,
            )
            persona.is_available = result.available
            persona.unavailable_reason = result.unavailable_reason
            if not result.available:
                continue

            auth_stats["personas_available"] += 1
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
) -> list[SurfaceMap]:
    """``root_url`` defaults to the target's own root URL; tests pass an
    explicit one — see _run_auth_establishing's docstring for why."""
    scope_guard = build_scope_guard(target, scope_rules)
    rate_limiter = RateLimiter(redis_client)
    crawler = PersonaCrawler(
        scope_guard=scope_guard, rate_limiter=rate_limiter, target_id=str(target.id)
    )
    effective_root_url = root_url or f"https://{target.root_domain}/"

    surfaces: list[SurfaceMap] = [
        await crawler.crawl(browser, root_url=effective_root_url, persona_id="anonymous")
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
            )
        )
    return surfaces


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
        await _start_phase(session, phase)

        if not target.is_scannable:
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

            if auth_stats["personas_available"] == 0:
                # Every configured persona failed to log in at all — the
                # state machine's genuine FAILED_AUTH case (docs/01 §5),
                # distinct from "some personas unavailable but others work".
                machine.transition(ScanState.FAILED_AUTH)
                scan.state = machine.current
                await _finish_phase(
                    session,
                    phase,
                    status=PhaseStatus.FAILED,
                    stats=auth_stats,
                    error="All configured personas failed to establish a session.",
                )
                scan.finished_at = datetime.now(UTC)
                await session.commit()
                log.info("scan_runner.failed_auth", scan_id=scan_id)
                return

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

        # --- Everything past this point is M2+ (docs/05-v1-roadmap.md) ---
        machine.transition(ScanState.PAUSED)
        scan.state = machine.current
        scan.paused_from = machine.paused_from
        scan.is_degraded = True
        scan.degraded_reasons = [*scan.degraded_reasons, NOT_YET_IMPLEMENTED_NOTE]
        await session.commit()

        log.info(
            "scan_runner.paused_after_surface_mapping",
            scan_id=scan_id,
            assets_found=len(recon_result.assets),
            personas_crawled=len(surfaces),
            endpoints_created=total_created,
        )
