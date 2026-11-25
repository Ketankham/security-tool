"""ScanAuthorisation: the record that a named, signed-in person confirmed they
are authorised to run active tools (port scanning, directory brute forcing)
against a target, for one scan.

Written in the same transaction as the Scan, before the scan is dispatched,
so a scan that used an active tool always has one. The worker refuses to run
an active tool when this row is missing or names nobody (fail closed). The
statement text is stored as it was shown, so the record stays true if the
wording changes later.

No ORM relationships: the table has two foreign keys to ``scans`` (the scan
itself, and the earlier scan an authorisation was carried over from on a
retry), and everything that reads it queries by ``scan_id``.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, String
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from ..base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class ScanAuthorisation(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "scan_authorisations"

    scan_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), unique=True, index=True
    )
    target_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("targets.id", ondelete="CASCADE"), index=True
    )
    # Who confirmed: the verified identity the API got from the sign-in proxy.
    username: Mapped[str] = mapped_column(String(64))
    accepted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    statement_version: Mapped[str] = mapped_column(String(20))
    statement_text: Mapped[str] = mapped_column(String(2000))
    client_name: Mapped[str] = mapped_column(String(200))
    target_name: Mapped[str] = mapped_column(String(255))
    # The active tools this confirmation covers, e.g. ["dir_bruteforce", "port_scan"].
    tools: Mapped[list[str]] = mapped_column(JSONB, default=list)
    all_ports_confirmed: Mapped[bool] = mapped_column(Boolean, default=False)
    target_environment: Mapped[str] = mapped_column(String(20))  # production | staging
    options_snapshot: Mapped[dict] = mapped_column(JSONB, default=dict)
    client_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(300), nullable=True)
    # Set when this scan is a retry that was confirmed again, pointing at the scan it retried.
    carried_over_from_scan_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("scans.id", ondelete="SET NULL"), nullable=True
    )
