"""TranscriptRecord: a lightweight DB index over evidence stored in
sentinel_core.transcript (local disk in dev, R2/S3 in prod). The DB row
lets us query/list evidence by scan/persona without touching object
storage; the actual bytes live at the content-addressed transcript_id.
"""

from __future__ import annotations

import uuid

from sqlalchemy import ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column

from ..base import Base, TimestampMixin


class TranscriptRecord(TimestampMixin, Base):
    __tablename__ = "transcript_records"

    # The content hash IS the id — see sentinel_core.transcript.store.
    transcript_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    scan_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), index=True
    )
    persona_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("personas.id"), nullable=True)
    method: Mapped[str] = mapped_column(String(10))
    url: Mapped[str] = mapped_column(String(2000))
    status_code: Mapped[int | None] = mapped_column(nullable=True)
