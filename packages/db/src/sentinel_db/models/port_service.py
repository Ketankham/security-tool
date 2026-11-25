"""PortService: one TCP port found open on one address of the target, with what
is known about the service behind it.

``confidence``:
  detected    nmap (service/version detection) named the service by talking to it
  port_guess  only the port NUMBER was used to name the service (see
              sentinel_recon.port_guess): conventional, never verified, and shown
              to a reader as "unverified"

``found_by`` says which tool last wrote the row: ``naabu`` found the port open,
``nmap`` also examined it. One row per (scan, ip, port, protocol); ``hosts`` are
the in-scope host names that resolved to that address.

``scripts`` holds nmap script output (id -> text), already redacted and capped
by the wrapper before it gets here. The report never includes it.
"""

from __future__ import annotations

import uuid

from sqlalchemy import ForeignKey, Integer, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from ..base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class PortService(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "port_services"
    __table_args__ = (
        UniqueConstraint("scan_id", "ip", "port", "protocol", name="uq_port_services_scan_ip_port"),
    )

    scan_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), index=True
    )
    tool_run_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("tool_runs.id", ondelete="SET NULL"), nullable=True
    )
    ip: Mapped[str] = mapped_column(String(64))
    hosts: Mapped[list[str]] = mapped_column(JSONB, default=list)
    port: Mapped[int] = mapped_column(Integer)
    protocol: Mapped[str] = mapped_column(String(10), default="tcp")
    state: Mapped[str] = mapped_column(String(20))  # open | closed | filtered | ...
    service: Mapped[str | None] = mapped_column(String(100), nullable=True)
    product: Mapped[str | None] = mapped_column(String(200), nullable=True)
    version: Mapped[str | None] = mapped_column(String(100), nullable=True)
    extra_info: Mapped[str | None] = mapped_column(String(300), nullable=True)
    confidence: Mapped[str] = mapped_column(String(20))  # detected | port_guess
    scripts: Mapped[dict[str, str]] = mapped_column(JSONB, default=dict)
    cdn: Mapped[str | None] = mapped_column(String(100), nullable=True)
    found_by: Mapped[str] = mapped_column(String(20))  # naabu | nmap
