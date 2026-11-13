"""Scan lifecycle endpoints. Creating a scan transitions nothing by itself —
the worker (apps/worker, Task via Celery) owns walking the state machine
(sentinel_core.state_machine.ScanStateMachine). This router only creates the
QUEUED row and asks the broker to pick it up (docs/01 §5).
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sentinel_core.state_machine import TERMINAL_STATES, ScanState
from sentinel_db.models import Organization, Scan, Target
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from ..celery_client import dispatch_scan
from ..config import get_settings
from ..deps import get_current_org, get_owned_target, get_session
from ..schemas.scan import ScanCreate, ScanOut

router = APIRouter(tags=["scans"])


@router.post(
    "/targets/{target_id}/scans", response_model=ScanOut, status_code=status.HTTP_201_CREATED
)
async def create_scan(
    payload: ScanCreate,
    target: Target = Depends(get_owned_target),
    session: AsyncSession = Depends(get_session),
) -> Scan:
    if get_settings().require_ownership_verification and not target.is_scannable:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "Target is not scannable yet — ownership must be verified and authorization "
            "accepted first (see docs/06-safety-legal-abuse.md §1).",
        )

    return await _start_scan(
        session,
        target,
        triggered_by=payload.triggered_by,
        options={"speed": payload.speed, "depth": payload.depth},
    )


async def _start_scan(
    session: AsyncSession, target: Target, *, triggered_by: str, options: dict
) -> Scan:
    scan = Scan(target_id=target.id, triggered_by=triggered_by, options=options)
    session.add(scan)
    await session.commit()

    if not dispatch_scan(str(scan.id)):
        # Nothing will ever pick this scan up; say so now instead of leaving
        # it "Queued" forever. Retry works once the queue is back.
        scan.state = ScanState.FAILED
        scan.fail_reason = (
            "The scan could not be handed to the scan worker (the job queue is unreachable). "
            "Use Retry in a minute; if it keeps failing, check the redis and worker containers."
        )
        scan.finished_at = datetime.now(UTC)
        await session.commit()

    # Re-fetch with phases eagerly (selectin) loaded: assigning or reading
    # scan.phases directly here would trigger an implicit lazy load, which
    # AsyncSession forbids outside an explicit await — the same rule this
    # product's own crawler relies on to never do surprise I/O either.
    result = await session.execute(
        select(Scan).where(Scan.id == scan.id).options(selectinload(Scan.phases))
    )
    return result.scalar_one()


@router.post("/scans/{scan_id}/retry", response_model=ScanOut, status_code=status.HTTP_201_CREATED)
async def retry_scan(
    scan_id: UUID,
    org: Organization = Depends(get_current_org),
    session: AsyncSession = Depends(get_session),
) -> Scan:
    """Start a fresh scan of the same target. The old scan stays as it was
    (its findings and failure reason are history); only a scan that has
    finished, one way or another, can be retried."""
    old = await _org_scan(session, scan_id, org)
    if old.state not in TERMINAL_STATES:
        raise HTTPException(
            status.HTTP_409_CONFLICT, "This scan is still running; wait for it to finish."
        )
    target = await session.get(Target, old.target_id)
    assert target is not None  # FK + the join in _org_scan
    if get_settings().require_ownership_verification and not target.is_scannable:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN, "Target is not scannable yet — verify ownership first."
        )
    # Same speed / depth as the scan being retried.
    return await _start_scan(session, target, triggered_by="retry", options=dict(old.options or {}))


@router.get("/targets/{target_id}/scans", response_model=list[ScanOut])
async def list_scans(
    target: Target = Depends(get_owned_target),
    session: AsyncSession = Depends(get_session),
) -> list[Scan]:
    result = await session.execute(
        select(Scan).where(Scan.target_id == target.id).options(selectinload(Scan.phases))
    )
    return list(result.scalars().all())


@router.get("/scans/{scan_id}", response_model=ScanOut)
async def get_scan(
    scan_id: UUID,
    org: Organization = Depends(get_current_org),
    session: AsyncSession = Depends(get_session),
) -> Scan:
    return await _org_scan(session, scan_id, org)


async def _org_scan(session: AsyncSession, scan_id: UUID, org: Organization) -> Scan:
    # Joined through Target so this can never return a scan belonging to
    # another org's target — the exact class of bug this product exists to
    # find (docs/03 §4 — horizontal/IDOR), so it does not get to exist here.
    result = await session.execute(
        select(Scan)
        .join(Target, Scan.target_id == Target.id)
        .where(Scan.id == scan_id, Target.organization_id == org.id)
        .options(selectinload(Scan.phases))
    )
    scan = result.scalar_one_or_none()
    if scan is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Scan not found.")
    return scan
