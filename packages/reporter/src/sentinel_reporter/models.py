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

    def to_dict(self) -> dict:
        return {
            "host": self.host,
            "discovery_source": self.discovery_source,
            "ip_addresses": list(self.ip_addresses),
            "tech_fingerprint": list(self.tech_fingerprint),
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

    @property
    def summary(self) -> dict:
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
            "is_degraded": self.is_degraded,
            "degraded_reasons": list(self.degraded_reasons),
            "scope_note": (
                "This scan ran recon, crawling, and surface mapping"
                + (", and the authorization engine" if len(self.personas_crawled) > 1 else "")
                + ". Passive/config checks, injection testing, and session-management checks "
                "are not implemented yet (docs/05-v1-roadmap.md M3) — their absence from "
                "`findings` means they didn't run, not that the target is clean."
            ),
        }
