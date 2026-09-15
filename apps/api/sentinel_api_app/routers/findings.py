"""Findings — read-only from this API; every field here is produced by the
worker's checks/verifier/triage pipeline (docs/02 Phases 6-10), never
written directly through this router."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sentinel_db.models import Finding, Organization, Scan, Target
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from ..deps import get_current_org, get_session
from ..schemas.finding import FindingOut

router = APIRouter(tags=["findings"])


@router.get("/scans/{scan_id}/findings", response_model=list[FindingOut])
async def list_findings(
    scan_id: str,
    org: Organization = Depends(get_current_org),
    session: AsyncSession = Depends(get_session),
) -> list[Finding]:
    # Same org-ownership join as GET /scans/{id} — a finding is reachable
    # only through a scan whose target belongs to the caller's org.
    scan_check = await session.execute(
        select(Scan.id)
        .join(Target, Scan.target_id == Target.id)
        .where(Scan.id == scan_id, Target.organization_id == org.id)
    )
    if scan_check.scalar_one_or_none() is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Scan not found.")

    result = await session.execute(
        select(Finding)
        .where(Finding.scan_id == scan_id)
        .options(selectinload(Finding.evidence), selectinload(Finding.verification))
    )
    return list(result.scalars().all())
