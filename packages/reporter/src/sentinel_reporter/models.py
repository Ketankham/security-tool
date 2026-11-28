"""ScanReport: the deliverable docs/02-scan-lifecycle.md Phase 11 describes,
scoped to what M2 slice 2 actually produces — a recon/surface inventory plus
whatever findings the check engines built so far (M2: authorization only;
M3 will add passive/injection/session).

Deliberately plain dataclasses with a hand-written ``to_dict()`` rather than
a generic serializer: this is the one place the shape of "the report" is
decided, and an explicit method makes that shape a reviewable diff instead
of whatever a library's default JSON encoding happens to produce. Kept
DB-agnostic like every other check/report package — apps/worker's adapter
builds one from ORM data.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime


@dataclass(frozen=True, slots=True)
class ReportAsset:
    host: str
    discovery_source: str
    ip_addresses: list[str] = field(default_factory=list)
    tech_fingerprint: list[str] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
    scope_status: str = "in_scope"
    live: bool = False

    def to_dict(self) -> dict:
        return {
            "host": self.host,
            "discovery_source": self.discovery_source,
            "ip_addresses": list(self.ip_addresses),
            "tech_fingerprint": list(self.tech_fingerprint),
            "sources": list(self.sources),
            "scope_status": self.scope_status,
            "live": self.live,
        }


@dataclass(frozen=True, slots=True)
class ReportEndpoint:
    method: str
    path_template: str
    discovery_source: str
    discovered_by_persona_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "method": self.method,
            "path_template": self.path_template,
            "discovery_source": self.discovery_source,
            "discovered_by_persona_ids": list(self.discovered_by_persona_ids),
        }


@dataclass(frozen=True, slots=True)
class ReportFinding:
    rule_id: str
    title: str
    severity: str
    confidence: str

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "confidence": self.confidence,
        }


@dataclass(frozen=True, slots=True)
class ReportPath:
    """A path found by directory brute force. Names, status and size only:
    no file content is ever part of a report."""

    origin: str
    path: str
    url: str
    method: str
    status_code: int
    category: str
    verdict: str  # confirmed | not_confirmed | found
    wordlist: str
    content_length: int | None = None
    content_type: str | None = None
    redirect_location: str | None = None
    rule_id: str | None = None
    note: str | None = None
    crawl_seed: bool = False

    def to_dict(self) -> dict:
        return {
            "origin": self.origin,
            "path": self.path,
            "url": self.url,
            "method": self.method,
            "status_code": self.status_code,
            "content_length": self.content_length,
            "content_type": self.content_type,
            "redirect_location": self.redirect_location,
            "category": self.category,
            "wordlist": self.wordlist,
            "verdict": self.verdict,
            "rule_id": self.rule_id,
            "note": self.note,
            "crawl_seed": self.crawl_seed,
        }


@dataclass(frozen=True, slots=True)
class ReportPort:
    """An open TCP port found by port scanning. ``confidence`` is "detected"
    (nmap named the service) or "port_guess" (named from the port number alone,
    unverified). nmap script output is deliberately NOT part of the report."""

    ip: str
    port: int
    state: str
    confidence: str
    found_by: str
    protocol: str = "tcp"
    hosts: list[str] = field(default_factory=list)
    service: str | None = None
    product: str | None = None
    version: str | None = None
    cdn: str | None = None

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "hosts": list(self.hosts),
            "port": self.port,
            "protocol": self.protocol,
            "state": self.state,
            "service": self.service,
            "product": self.product,
            "version": self.version,
            "confidence": self.confidence,
            "found_by": self.found_by,
            "cdn": self.cdn,
        }


@dataclass(frozen=True, slots=True)
class ReportAuthorisation:
    """Who confirmed they were authorised to run the scan's active tools."""

    username: str
    accepted_at: datetime
    client_name: str
    tools: list[str]
    statement_version: str
    statement_text: str
    target_environment: str

    def to_dict(self) -> dict:
        return {
            "username": self.username,
            "accepted_at": self.accepted_at.isoformat(),
            "client_name": self.client_name,
            "tools": list(self.tools),
            "statement_version": self.statement_version,
            "statement_text": self.statement_text,
            "target_environment": self.target_environment,
        }


@dataclass(frozen=True, slots=True)
class ScanReport:
    scan_id: str
    target_root_domain: str
    target_display_name: str
    generated_at: datetime
    personas_crawled: list[str]
    assets: list[ReportAsset]
    endpoints: list[ReportEndpoint]
    findings: list[ReportFinding]
    is_degraded: bool
    degraded_reasons: list[str]
    # Names of the check groups that ran / were skipped in this scan (for
    # the scope note). Both empty: the caller did not say, and the note falls
    # back to the generic wording.
    checks_run: list[str] = field(default_factory=list)
    checks_skipped: list[str] = field(default_factory=list)
    # Directory brute force results, and the authorisation behind the scan's
    # active tools. Both are empty/None for a passive scan.
    paths: list[ReportPath] = field(default_factory=list)
    # Port scanning results (open ports and services); empty without that tool.
    ports: list[ReportPort] = field(default_factory=list)
    authorisation: ReportAuthorisation | None = None

    @property
    def summary(self) -> dict:
        summary = self._base_summary()
        if self.paths:
            summary["paths_found"] = len(self.paths)
            summary["paths_confirmed"] = sum(1 for p in self.paths if p.verdict == "confirmed")
        if self.ports:
            open_ports = [p for p in self.ports if p.state == "open"]
            summary["open_ports"] = len(open_ports)
            summary["ips_with_open_ports"] = len({p.ip for p in open_ports})
            summary["ports_unverified"] = sum(1 for p in open_ports if p.confidence != "detected")
        return summary

    def _base_summary(self) -> dict:
        return {
            "assets_found": len(self.assets),
            "endpoints_found": len(self.endpoints),
            "personas_crawled": len(self.personas_crawled),
            "findings_confirmed": sum(1 for f in self.findings if f.confidence == "confirmed"),
            "findings_probable": sum(1 for f in self.findings if f.confidence == "probable"),
        }

    def to_dict(self) -> dict:
        return {
            "scan_id": self.scan_id,
            "target": {
                "root_domain": self.target_root_domain,
                "display_name": self.target_display_name,
            },
            "generated_at": self.generated_at.isoformat(),
            "summary": self.summary,
            "personas_crawled": list(self.personas_crawled),
            "assets": [a.to_dict() for a in self.assets],
            "endpoints": [e.to_dict() for e in self.endpoints],
            "findings": [f.to_dict() for f in self.findings],
            "paths": [p.to_dict() for p in self.paths],
            "ports": [p.to_dict() for p in self.ports],
            "authorisation": self.authorisation.to_dict() if self.authorisation else None,
            "is_degraded": self.is_degraded,
            "degraded_reasons": list(self.degraded_reasons),
            "checks_run": list(self.checks_run),
            "checks_skipped": list(self.checks_skipped),
            "scope_note": self._scope_note(),
        }

    def _scope_note(self) -> str:
        if self.checks_run or self.checks_skipped:
            ran = ", ".join(self.checks_run) or "no checks"
            note = f"This scan ran recon, crawling and surface mapping, then: {ran}."
            if self.checks_skipped:
                note += (
                    f" Not run: {', '.join(self.checks_skipped)}. Their absence from `findings` "
                    "means they did not run, not that the target is clean."
                )
            return note
        return (
            "This scan ran recon, crawling, and surface mapping"
            + (", and the authorization engine" if len(self.personas_crawled) > 1 else "")
            + ". Passive/config checks, injection testing, and session-management checks "
            "may not have run (docs/05-v1-roadmap.md M3) — their absence from "
            "`findings` means they didn't run, not that the target is clean."
        )
