"""Builds a sentinel_reporter.ScanReport from a scan's persisted Asset/
Endpoint/Finding rows and stores it via a content-addressed TranscriptStore,
returning a Report ORM object ready for the caller to add to its session.
Same "build, don't persist" convention as access_control_adapter.py.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

from sentinel_core.transcript import TranscriptStore
from sentinel_db.enums import ReportFormat
from sentinel_db.models import Asset, Finding, Report, Scan, Target
from sentinel_reporter import ReportAsset, ReportEndpoint, ReportFinding, ScanReport
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload


async def build_scan_report(
    session: AsyncSession, *, scan: Scan, target: Target, personas_crawled: list[str]
) -> ScanReport:
    assets = (
        (
            await session.execute(
                select(Asset).where(Asset.scan_id == scan.id).options(selectinload(Asset.endpoints))
            )
        )
        .scalars()
        .all()
    )
    report_assets = [
        ReportAsset(
            host=a.host,
            discovery_source=a.discovery_source,
            ip_addresses=a.ip_addresses,
            tech_fingerprint=a.tech_fingerprint,
        )
        for a in assets
    ]
    report_endpoints = [
        ReportEndpoint(
            method=e.method,
            path_template=e.path_template,
            discovery_source=e.discovery_source,
            discovered_by_persona_ids=e.discovered_by_persona_ids,
        )
        for a in assets
        for e in a.endpoints
    ]

    findings = (
        (await session.execute(select(Finding).where(Finding.scan_id == scan.id))).scalars().all()
    )
    report_findings = [
        ReportFinding(
            rule_id=f.rule_id,
            title=f.title,
            severity=f.severity.value,
            confidence=f.confidence.value,
        )
        for f in findings
    ]

    return ScanReport(
        scan_id=str(scan.id),
        target_root_domain=target.root_domain,
        target_display_name=target.display_name,
        generated_at=datetime.now(UTC),
        personas_crawled=personas_crawled,
        assets=report_assets,
        endpoints=report_endpoints,
        findings=report_findings,
        is_degraded=scan.is_degraded,
        degraded_reasons=list(scan.degraded_reasons),
    )


async def persist_report(report: ScanReport, *, scan: Scan, store: TranscriptStore) -> Report:
    payload = json.dumps(report.to_dict(), default=str).encode()
    storage_pointer = await store.put(payload, content_type="application/json")
    return Report(scan_id=scan.id, format=ReportFormat.DASHBOARD, storage_pointer=storage_pointer)
