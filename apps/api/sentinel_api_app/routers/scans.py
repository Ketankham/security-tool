"""Scan lifecycle endpoints. Creating a scan transitions nothing by itself —
the worker (apps/worker, Task via Celery) owns walking the state machine
(sentinel_core.state_machine.ScanStateMachine). This router only creates the
QUEUED row and asks the broker to pick it up (docs/01 §5).
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sentinel_db.models import Organization, Scan, Target
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from ..celery_client import dispatch_scan
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
    if not target.is_scannable:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "Target is not scannable yet — ownership must be verified and authorization "
            "accepted first (see docs/06-safety-legal-abuse.md §1).",
        )

    scan = Scan(target_id=target.id, triggered_by=payload.triggered_by)
    session.add(scan)
    await session.commit()

    # Re-fetch with phases eagerly (selectin) loaded: assigning or reading
    # scan.phases directly here would trigger an implicit lazy load, which
    # AsyncSession forbids outside an explicit await — the same rule this
    # product's own crawler relies on to never do surprise I/O either.
    result = await session.execute(
        select(Scan).where(Scan.id == scan.id).options(selectinload(Scan.phases))
    )
    scan = result.scalar_one()

    dispatch_scan(str(scan.id))
    return scan


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
    scan_id: str,
    org: Organization = Depends(get_current_org),
    session: AsyncSession = Depends(get_session),
) -> Scan:
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
