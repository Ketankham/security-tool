from __future__ import annotations

from uuid import UUID

from pydantic import BaseModel, ConfigDict
from sentinel_db.enums import FindingConfidence, FindingSeverity, FindingStatus


class VerificationOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    reproduced_count: int
    attempted_count: int
    passed: bool


class EvidenceOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    transcript_id: str
    role: str
    note: str


class FindingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    scan_id: UUID
    fingerprint: str
    rule_id: str
    title: str
    cwe: list[int]
    owasp_top10: str | None
    cvss_vector: str | None
    severity: FindingSeverity
    confidence: FindingConfidence
    status: FindingStatus
    narrative: str
    remediation: dict
    reproduction: dict
    evidence: list[EvidenceOut] = []
    verification: VerificationOut | None = None
