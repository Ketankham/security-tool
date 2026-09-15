from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column

from ..base import Base, TimestampMixin, UUIDPrimaryKeyMixin
from ..enums import ReportFormat


class Report(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """A generated deliverable (docs/02 Phase 11). ATTESTATION_LETTER rows
    are the Verified-tier product (docs/00 §7) and are the only ones that
    ever get verified_by/verified_at populated."""

    __tablename__ = "reports"

    scan_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), index=True
    )
    format: Mapped[ReportFormat]
    storage_pointer: Mapped[str] = mapped_column(
        String(500)
    )  # transcript-store key or R2 object key

    verified_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id"), nullable=True
    )
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
