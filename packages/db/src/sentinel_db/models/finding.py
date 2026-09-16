"""Finding, Evidence, Verification.

The single most important structural invariant in the whole schema lives
here (docs/01-architecture.md §6.6, ADR-0001): a Finding can only carry
confidence=CONFIRMED if it has a linked Verification that actually passed
reproduction >=2 times. This is enforced with a `before_flush` event below,
not just by convention — "AI proposes, deterministic replay disposes" has
to be a property of the database, or it's just a comment.
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, event
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, Session, mapped_column, relationship

from ..base import Base, TimestampMixin, UUIDPrimaryKeyMixin
from ..enums import FindingConfidence, FindingSeverity, FindingStatus

if TYPE_CHECKING:
    pass

MIN_REPRODUCTIONS_FOR_CONFIRMED = 2


class Verification(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Phase 9 (docs/02 §Phase 9) — purely deterministic re-execution of a
    candidate finding, independent of however it was originally proposed."""

    __tablename__ = "verifications"

    finding_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"), unique=True, index=True
    )
    reproduced_count: Mapped[int] = mapped_column(Integer, default=0)
    attempted_count: Mapped[int] = mapped_column(Integer, default=0)
    passed: Mapped[bool] = mapped_column(Boolean, default=False)
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    details: Mapped[dict] = mapped_column(JSONB, default=dict)

    finding: Mapped[Finding] = relationship(back_populates="verification")

    @property
    def satisfies_confirmed(self) -> bool:
        return self.passed and self.reproduced_count >= MIN_REPRODUCTIONS_FOR_CONFIRMED


class Evidence(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "evidence"

    finding_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"), index=True
    )
    transcript_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("transcript_records.transcript_id")
    )
    role: Mapped[str] = mapped_column(String(100))  # "request-as-admin", "replay-as-viewer", ...
    note: Mapped[str] = mapped_column(String(1000), default="")

    finding: Mapped[Finding] = relationship(back_populates="evidence")


class Finding(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "findings"

    scan_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), index=True
    )

    # Stable across scans: hash(rule_id, endpoint_template, param, persona_pair)
    # — this is what makes dedup/regression-detection across scans a lookup
    # rather than a fuzzy match (docs/01 §6.6, docs/04 §C5).
    fingerprint: Mapped[str] = mapped_column(String(64), index=True)

    rule_id: Mapped[str] = mapped_column(String(100), index=True)  # "authz.horizontal.idor"
    title: Mapped[str] = mapped_column(String(300))
    cwe: Mapped[list[int]] = mapped_column(JSONB, default=list)
    owasp_top10: Mapped[str | None] = mapped_column(String(20), nullable=True)
    cvss_vector: Mapped[str | None] = mapped_column(String(100), nullable=True)

    severity: Mapped[FindingSeverity] = mapped_column(index=True)
    confidence: Mapped[FindingConfidence] = mapped_column(
        default=FindingConfidence.PROBABLE, index=True
    )
    status: Mapped[FindingStatus] = mapped_column(default=FindingStatus.OPEN, index=True)

    reproduction: Mapped[dict] = mapped_column(
        JSONB, default=dict
    )  # includes a copy-pasteable curl
    narrative: Mapped[str] = mapped_column(String(10_000), default="")
    remediation: Mapped[dict] = mapped_column(JSONB, default=dict)

    first_seen_scan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scans.id"))
    last_seen_scan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scans.id"))

    evidence: Mapped[list[Evidence]] = relationship(
        back_populates="finding", cascade="all, delete-orphan"
    )
    verification: Mapped[Verification | None] = relationship(
        back_populates="finding", uselist=False, cascade="all, delete-orphan"
    )

    @staticmethod
    def compute_fingerprint(
        *, rule_id: str, endpoint_template: str, param: str, persona_pair: str
    ) -> str:
        raw = f"{rule_id}|{endpoint_template}|{param}|{persona_pair}"
        return hashlib.sha256(raw.encode()).hexdigest()


@event.listens_for(Session, "before_flush")
def _enforce_confirmed_requires_verification(session: Session, flush_context, instances) -> None:
    """The structural half of ADR-0001: `confidence=CONFIRMED` is only
    persistable alongside a Verification that actually passed reproduction.
    Anything else (an LLM's opinion, an unverified candidate) is downgraded
    to PROBABLE right here — deliberately a hard stop, not a warning."""
    candidates = [
        obj
        for obj in list(session.new) + list(session.dirty)
        if isinstance(obj, Finding) and obj.confidence == FindingConfidence.CONFIRMED
    ]
    for finding in candidates:
        verification = finding.verification
        if verification is None or not verification.satisfies_confirmed:
            raise ValueError(
                f"Finding {finding.id} (rule={finding.rule_id!r}) cannot be persisted with "
                "confidence=CONFIRMED without a linked Verification where passed=True and "
                f"reproduced_count >= {MIN_REPRODUCTIONS_FOR_CONFIRMED}. "
                "See docs/adr/0001-engine-split-ai-vs-deterministic.md — "
                "the LLM never has the last word."
            )
