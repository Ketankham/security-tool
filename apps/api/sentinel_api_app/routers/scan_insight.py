"""What a scan did, for people who need to check it: the activity log, the
pages/endpoints it found, and the stored request/response behind a finding's
evidence. All read-only and org-scoped through get_owned_scan."""

from __future__ import annotations

import json

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import PlainTextResponse
from sentinel_core.transcript import LocalTranscriptStore
from sentinel_db.models import Asset, Endpoint, Scan, ScanEvent, TranscriptRecord
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import Settings, get_settings
from ..deps import get_owned_scan, get_session
from ..schemas.scan_insight import ScanEndpointOut, ScanEventOut, ScanEventsOut

router = APIRouter(tags=["scan-insight"])

_MAX_PAGE = 2000


@router.get("/scans/{scan_id}/events", response_model=ScanEventsOut)
async def list_scan_events(
    after_seq: int = Query(default=0, ge=0),
    limit: int = Query(default=500, ge=1, le=_MAX_PAGE),
    stage: str | None = None,
    persona: str | None = None,
    level: str | None = None,
    scan: Scan = Depends(get_owned_scan),
    session: AsyncSession = Depends(get_session),
) -> ScanEventsOut:
    query = select(ScanEvent).where(ScanEvent.scan_id == scan.id, ScanEvent.seq > after_seq)
    if stage:
        query = query.where(ScanEvent.stage == stage)
    if persona:
        query = query.where(ScanEvent.persona == persona)
    if level:
        query = query.where(ScanEvent.level == level)
    rows = (await session.execute(query.order_by(ScanEvent.seq).limit(limit))).scalars().all()
    total = (
        await session.execute(
            select(func.count()).select_from(ScanEvent).where(ScanEvent.scan_id == scan.id)
        )
    ).scalar_one()
    return ScanEventsOut(
        events=[ScanEventOut.model_validate(r) for r in rows],
        total=total,
        last_seq=rows[-1].seq if rows else after_seq,
    )


@router.get("/scans/{scan_id}/events/download", response_class=PlainTextResponse)
async def download_scan_log(
    scan: Scan = Depends(get_owned_scan),
    session: AsyncSession = Depends(get_session),
) -> PlainTextResponse:
    rows = (
        (
            await session.execute(
                select(ScanEvent).where(ScanEvent.scan_id == scan.id).order_by(ScanEvent.seq)
            )
        )
        .scalars()
        .all()
    )
    lines = [
        f"{r.at.isoformat(timespec='seconds')} [{r.level.upper():5}] [{r.stage}]"
        + (f" [{r.persona}]" if r.persona else "")
        + f" {r.message}"
        for r in rows
    ]
    header = (
        f"# Sentinel scan {scan.id}\n# state: {scan.state.value}"
        + (f"\n# failure: {scan.fail_reason}" if scan.fail_reason else "")
        + f"\n# {len(rows)} line(s). Secrets (passwords, cookies, tokens) are redacted.\n"
    )
    return PlainTextResponse(
        header + "\n".join(lines) + "\n",
        headers={"Content-Disposition": f'attachment; filename="scan-{str(scan.id)[:8]}-log.txt"'},
    )


@router.get("/scans/{scan_id}/endpoints", response_model=list[ScanEndpointOut])
async def list_scan_endpoints(
    scan: Scan = Depends(get_owned_scan),
    session: AsyncSession = Depends(get_session),
) -> list[ScanEndpointOut]:
    rows = (
        await session.execute(
            select(Asset.host, Endpoint)
            .join(Endpoint, Endpoint.asset_id == Asset.id)
            .where(Asset.scan_id == scan.id)
            .order_by(Asset.host, Endpoint.path_template, Endpoint.method)
        )
    ).all()
    return [
        ScanEndpointOut(
            host=host,
            method=ep.method,
            path_template=ep.path_template,
            source=ep.discovery_source,
            persona_ids=list(ep.discovered_by_persona_ids),
        )
        for host, ep in rows
    ]


@router.get("/scans/{scan_id}/transcripts/{transcript_id}")
async def get_scan_transcript(
    transcript_id: str,
    scan: Scan = Depends(get_owned_scan),
    session: AsyncSession = Depends(get_session),
    settings: Settings = Depends(get_settings),
) -> dict:
    """The stored (already secret-scrubbed) request and response behind a
    finding's evidence, so a reviewer can check it by hand."""
    known = await session.execute(
        select(TranscriptRecord.transcript_id).where(
            TranscriptRecord.transcript_id == transcript_id, TranscriptRecord.scan_id == scan.id
        )
    )
    if known.scalar_one_or_none() is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Transcript not found for this scan.")
    store = LocalTranscriptStore(settings.storage_local_path)
    try:
        raw = await store.get(transcript_id)
    except FileNotFoundError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Transcript content is missing.") from exc
    doc = json.loads(raw)
    # Bound what the browser has to render.
    response = doc.get("response")
    if (
        isinstance(response, dict)
        and isinstance(response.get("body"), str)
        and len(response["body"]) > 20_000
    ):
        response["body"] = response["body"][:20_000] + "\n… (truncated)"
    return doc
