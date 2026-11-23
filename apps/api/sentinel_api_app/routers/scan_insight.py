"""What a scan did, for people who need to check it: the activity log, the
pages/endpoints it found, and the stored request/response behind a finding's
evidence. All read-only and org-scoped through get_owned_scan."""

from __future__ import annotations

import json
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import PlainTextResponse
from sentinel_core.transcript import LocalTranscriptStore
from sentinel_db.models import Asset, Endpoint, Scan, ScanEvent, ToolRunRecord, TranscriptRecord
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import Settings, get_settings
from ..deps import get_owned_scan, get_session
from ..schemas.scan_insight import (
    ScanAssetOut,
    ScanEndpointOut,
    ScanEventOut,
    ScanEventsOut,
    ToolRunOut,
)

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


_PREVIEW_CHARS = 4000


@router.get("/scans/{scan_id}/tool-runs", response_model=list[ToolRunOut])
async def list_tool_runs(
    scan: Scan = Depends(get_owned_scan),
    session: AsyncSession = Depends(get_session),
) -> list[ToolRunOut]:
    """Every tool the scan ran (subfinder, httpx, the built-in DNS and HTTP
    probers): the exact command, version, timing, exit code and a preview
    of what it printed."""
    rows = (
        (
            await session.execute(
                select(ToolRunRecord)
                .where(ToolRunRecord.scan_id == scan.id)
                .order_by(ToolRunRecord.seq)
            )
        )
        .scalars()
        .all()
    )
    return [
        ToolRunOut(
            id=r.id,
            seq=r.seq,
            phase=r.phase,
            tool=r.tool,
            binary=r.binary,
            version=r.version,
            command=r.command,
            status=r.status,
            skip_reason=r.skip_reason,
            started_at=r.started_at,
            finished_at=r.finished_at,
            duration_ms=r.duration_ms,
            exit_code=r.exit_code,
            timed_out=r.timed_out,
            results_count=r.results_count,
            stdout_chars=len(r.stdout),
            stderr_chars=len(r.stderr),
            stdout_truncated=r.stdout_truncated,
            stderr_truncated=r.stderr_truncated,
            stdout_preview=r.stdout[:_PREVIEW_CHARS],
            stderr_preview=r.stderr[:_PREVIEW_CHARS],
        )
        for r in rows
    ]


@router.get("/scans/{scan_id}/tool-runs/{run_id}/output", response_class=PlainTextResponse)
async def download_tool_output(
    run_id: uuid.UUID,
    stream: str = Query(default="stdout", pattern="^(stdout|stderr)$"),
    scan: Scan = Depends(get_owned_scan),
    session: AsyncSession = Depends(get_session),
) -> PlainTextResponse:
    run = (
        await session.execute(
            select(ToolRunRecord).where(
                ToolRunRecord.id == run_id, ToolRunRecord.scan_id == scan.id
            )
        )
    ).scalar_one_or_none()
    if run is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Tool run not found for this scan.")
    body = run.stdout if stream == "stdout" else run.stderr
    cut = run.stdout_truncated if stream == "stdout" else run.stderr_truncated
    header = f"# {run.tool} {run.version or ''} ({run.status}) — {stream}\n# $ {run.command}\n" + (
        "# Output was longer than the stored limit and is cut off.\n" if cut else ""
    )
    safe_tool = "".join(c if c.isalnum() else "-" for c in run.tool).strip("-")
    return PlainTextResponse(
        header + body + ("\n" if body and not body.endswith("\n") else ""),
        headers={
            "Content-Disposition": (
                f'attachment; filename="scan-{str(scan.id)[:8]}-{run.seq}-{safe_tool}-{stream}.txt"'
            )
        },
    )


@router.get("/scans/{scan_id}/assets", response_model=list[ScanAssetOut])
async def list_scan_assets(
    scan: Scan = Depends(get_owned_scan),
    session: AsyncSession = Depends(get_session),
) -> list[ScanAssetOut]:
    """Every host recon found (and every host the crawl reached), with where
    it came from, whether it was probed and, if not, why."""
    count_rows = (
        await session.execute(
            select(Endpoint.asset_id, func.count())
            .join(Asset, Asset.id == Endpoint.asset_id)
            .where(Asset.scan_id == scan.id)
            .group_by(Endpoint.asset_id)
        )
    ).all()
    counts: dict[uuid.UUID, int] = {row[0]: int(row[1]) for row in count_rows}
    assets = (
        (await session.execute(select(Asset).where(Asset.scan_id == scan.id).order_by(Asset.host)))
        .scalars()
        .all()
    )
    out = [
        ScanAssetOut(
            host=a.host,
            discovery_source=a.discovery_source,
            sources=list(a.sources or []),
            scope_status=a.scope_status,
            scope_reason=a.scope_reason,
            ip_addresses=list(a.ip_addresses or []),
            live=any(p.get("status_code") is not None for p in (a.http_probes or [])),
            tech=list(a.tech_fingerprint or []),
            http_probes=list(a.http_probes or []),
            endpoints=counts.get(a.id, 0),
        )
        for a in assets
    ]
    order = {"in_scope": 0, "excluded": 1, "private_ip": 2, "unresolved": 3, "capped": 4}
    out.sort(key=lambda a: (order.get(a.scope_status, 9), not a.live, a.host))
    return out


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
