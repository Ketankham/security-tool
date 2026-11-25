"""Builds a sentinel_reporter.ScanReport from a scan's persisted Asset/
Endpoint/Finding rows and stores it via a content-addressed TranscriptStore,
returning a Report ORM object ready for the caller to add to its session.
Same "build, don't persist" convention as access_control_adapter.py.
"""

from __future__ import annotations

import ipaddress
import json
from datetime import UTC, datetime

from sentinel_core import scan_options
from sentinel_core.transcript import TranscriptStore
from sentinel_db.enums import ReportFormat
from sentinel_db.models import (
    Asset,
    DiscoveredPath,
    Finding,
    PortService,
    Report,
    Scan,
    ScanAuthorisation,
    Target,
)
from sentinel_reporter import (
    ReportAsset,
    ReportAuthorisation,
    ReportEndpoint,
    ReportFinding,
    ReportPath,
    ReportPort,
    ScanReport,
)
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload


def _ip_key(ip: str) -> tuple[int, int, str]:
    """Numeric address order (IPv4 first); anything unparseable last."""
    try:
        address = ipaddress.ip_address(ip.split("%", 1)[0])
    except ValueError:
        return (2, 0, ip)
    return (0 if address.version == 4 else 1, int(address), ip)


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
            sources=a.sources or [],
            scope_status=a.scope_status or "in_scope",
            live=any(p.get("status_code") is not None for p in (a.http_probes or [])),
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

    path_rows = (
        (
            await session.execute(
                select(DiscoveredPath)
                .where(DiscoveredPath.scan_id == scan.id)
                .order_by(DiscoveredPath.category, DiscoveredPath.path, DiscoveredPath.origin)
            )
        )
        .scalars()
        .all()
    )
    report_paths = sorted(
        (
            ReportPath(
                origin=p.origin,
                path=p.path,
                url=p.url,
                method=p.method,
                status_code=p.status_code,
                category=p.category,
                verdict=p.verdict,
                wordlist=p.wordlist,
                content_length=p.content_length,
                content_type=p.content_type,
                redirect_location=p.redirect_location,
                rule_id=p.rule_id,
                note=p.note,
                crawl_seed=p.crawl_seed,
            )
            for p in path_rows
        ),
        key=lambda p: p.verdict != "confirmed",
    )
    port_rows = (
        (await session.execute(select(PortService).where(PortService.scan_id == scan.id)))
        .scalars()
        .all()
    )
    report_ports = [
        ReportPort(
            ip=p.ip,
            hosts=list(p.hosts or []),
            port=p.port,
            protocol=p.protocol,
            state=p.state,
            service=p.service,
            product=p.product,
            version=p.version,
            confidence=p.confidence,
            found_by=p.found_by,
            cdn=p.cdn,
        )
        for p in sorted(port_rows, key=lambda r: (_ip_key(r.ip), r.port, r.protocol))
    ]
    authorisation_row = (
        await session.execute(select(ScanAuthorisation).where(ScanAuthorisation.scan_id == scan.id))
    ).scalar_one_or_none()
    report_authorisation = (
        ReportAuthorisation(
            username=authorisation_row.username,
            accepted_at=authorisation_row.accepted_at,
            client_name=authorisation_row.client_name,
            tools=list(authorisation_row.tools or []),
            statement_version=authorisation_row.statement_version,
            statement_text=authorisation_row.statement_text,
            target_environment=authorisation_row.target_environment,
        )
        if authorisation_row is not None
        else None
    )

    # Which groups of checks actually ran (from the scan's own phase records).
    labels = {
        "passive_checks": "security headers, cookies, CORS, exposed files and TLS",
        "access_control": "authorization (who can reach what)",
        "active_injection": "injection testing",
        "session_checks": "session management",
        "business_logic": "business logic",
    }
    by_name = {p.name.value: p.status.value for p in scan.phases}
    checks_run = [text for key, text in labels.items() if by_name.get(key) == "completed"]
    checks_skipped = [text for key, text in labels.items() if by_name.get(key) == "skipped"]
    if "dir_bruteforce" in scan_options.active_tools(scan.options):
        recon_stats = next(
            (p.stats_json or {} for p in scan.phases if p.name.value == "recon"), {}
        ).get("dir_bruteforce")
        if recon_stats and recon_stats.get("hosts_run", 0) > 0:
            checks_run.append("directory and file brute force (active tool)")
        else:
            checks_skipped.append("directory and file brute force (active tool)")

    if "port_scan" in scan_options.active_tools(scan.options):
        port_stats = next(
            (p.stats_json or {} for p in scan.phases if p.name.value == "recon"), {}
        ).get("ports")
        if port_stats and port_stats.get("ips_scanned", 0) > 0:
            checks_run.append("port scanning and service detection (active tool)")
        else:
            checks_skipped.append("port scanning and service detection (active tool)")

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
        checks_run=checks_run,
        checks_skipped=checks_skipped,
        paths=report_paths,
        ports=report_ports,
        authorisation=report_authorisation,
    )


async def persist_report(report: ScanReport, *, scan: Scan, store: TranscriptStore) -> Report:
    payload = json.dumps(report.to_dict(), default=str).encode()
    storage_pointer = await store.put(payload, content_type="application/json")
    return Report(scan_id=scan.id, format=ReportFormat.DASHBOARD, storage_pointer=storage_pointer)
