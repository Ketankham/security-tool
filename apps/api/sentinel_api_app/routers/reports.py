"""GET /scans/{id}/report — reads back the ScanReport a completed scan's
REPORTING phase persisted (apps/worker/report_adapter.py). Read-only, same
org-ownership join as findings.py: a report is reachable only through a
scan whose target belongs to the caller's org."""

from __future__ import annotations

import json

from fastapi import APIRouter, Depends, HTTPException, status
from sentinel_core.transcript import LocalTranscriptStore
from sentinel_db.models import Organization, Report, Scan, Target
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import Settings, get_settings
from ..deps import get_current_org, get_session

router = APIRouter(tags=["reports"])


@router.get("/scans/{scan_id}/report")
async def get_scan_report(
    scan_id: str,
    org: Organization = Depends(get_current_org),
    session: AsyncSession = Depends(get_session),
    settings: Settings = Depends(get_settings),
) -> dict:
    scan_result = await session.execute(
        select(Scan)
        .join(Target, Scan.target_id == Target.id)
        .where(Scan.id == scan_id, Target.organization_id == org.id)
    )
    scan = scan_result.scalar_one_or_none()
    if scan is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Scan not found.")

    report_result = await session.execute(
        select(Report).where(Report.scan_id == scan_id).order_by(Report.created_at.desc())
    )
    report_row = report_result.scalars().first()
    if report_row is None:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND,
            f"No report yet for this scan (state={scan.state.value}) — a report is generated "
            "when the scan reaches its REPORTING phase.",
        )

    store = LocalTranscriptStore(settings.report_local_path)
    try:
        raw = await store.get(report_row.storage_pointer)
    except FileNotFoundError as exc:
        raise HTTPException(
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            "Report record exists but its stored content is missing.",
        ) from exc

    return json.loads(raw)
