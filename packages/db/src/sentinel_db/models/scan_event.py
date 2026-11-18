"""ScanEvent: one line of a scan's activity log.

The tester's complaint was "I cannot confirm whether it really works: there
are no logs to verify". These rows are that log: each stage, each login
attempt, every page the crawler visited or skipped (and why), every
authorization comparison. Written by the worker as the scan runs (so the
dashboard can show it live), read by GET /scans/{id}/events.

Messages are redacted before they are stored (sentinel_core.redact): the log
is shown in the UI and downloadable, so it must never hold a password,
cookie or token.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from ..base import Base, UUIDPrimaryKeyMixin


class ScanEvent(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "scan_events"
    __table_args__ = (UniqueConstraint("scan_id", "seq", name="uq_scan_events_scan_seq"),)

    scan_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), index=True
    )
    # 1, 2, 3... per scan, assigned by the single worker that runs the scan:
    # a stable order (timestamps can tie) and a cursor for "events after N".
    seq: Mapped[int] = mapped_column(Integer)
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    stage: Mapped[str] = mapped_column(String(40))  # recon | auth | crawl | ...
    level: Mapped[str] = mapped_column(String(10), default="info")  # info | warn | error
    # "anonymous", a persona's label, or None for scan-wide events.
    persona: Mapped[str | None] = mapped_column(String(200), nullable=True)
    message: Mapped[str] = mapped_column(String(1000))
    data: Mapped[dict] = mapped_column(JSONB, default=dict)
