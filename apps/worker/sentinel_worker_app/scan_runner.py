"""The scan orchestrator: walks sentinel_core.state_machine.ScanStateMachine
through the phases this milestone actually implements, persisting progress
after every step so a crashed worker resumes rather than restarts
(docs/01-architecture.md §5).

M0 scope (docs/05-v1-roadmap.md): SCOPE_VERIFYING and RECON are real. Every
phase after that — auth, crawl, the parallel TESTING phases, verify, triage,
report — is not implemented yet, so this orchestrator stops there, honestly:
it transitions the scan to PAUSED (not COMPLETE, and not a fake success)
with a clear degraded_reasons note, rather than claiming a finished scan
that never tested anything past recon (docs/04-edge-cases.md §G).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import structlog
from sentinel_core.state_machine import PhaseStatus, ScanPhaseName, ScanState, ScanStateMachine
from sentinel_db import open_session
from sentinel_db.models import Asset, Scan, ScanPhase, Target
from sentinel_recon import run_recon
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

log = structlog.get_logger(__name__)

NOT_YET_IMPLEMENTED_NOTE = (
    "Paused after recon — authentication, crawling, and all check phases are "
    "not implemented yet (see docs/05-v1-roadmap.md milestones M1-M3). This scan "
    "can be resumed once they land; it is not stuck or broken."
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


async def run_scan(scan_id: str) -> None:
    async with open_session() as session:
        # `selectinload` here matters, not just for speed: AsyncSession
        # forbids implicit lazy I/O on plain attribute access (`scan.phases`
        # below, in _get_or_create_phase) outside its own internal greenlet
        # context — the same MissingGreenlet trap the API hit (see
        # apps/api/app/routers/scans.py). Eager-load it up front instead.
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

        # --- Everything past this point is M1+ (docs/05-v1-roadmap.md) ---
        machine.transition(ScanState.PAUSED)
        scan.state = machine.current
        scan.paused_from = machine.paused_from
        scan.is_degraded = True
        scan.degraded_reasons = [*scan.degraded_reasons, NOT_YET_IMPLEMENTED_NOTE]
        await session.commit()

        log.info(
            "scan_runner.paused_after_recon",
            scan_id=scan_id,
            assets_found=len(recon_result.assets),
            degraded=recon_result.degraded,
        )
