"""ToolRunRecord: one tool invocation during a scan (subfinder, httpx, the
built-in DNS and HTTP probers...), with the exact command, the tool's
version, timings, exit code and its output.

The tester's ask was "verbose output": proof of what actually ran and what
it printed, not only the parsed result. Output is redacted and capped
before it is stored, and lives in the DB rather than on disk so deleting a
scan deletes it too (no orphaned files).
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from ..base import Base, TimestampMixin, UUIDPrimaryKeyMixin

MAX_STDOUT_CHARS = 512_000
MAX_STDERR_CHARS = 128_000


class ToolRunRecord(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "tool_runs"

    scan_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), index=True
    )
    seq: Mapped[int] = mapped_column(Integer)  # order within the scan
    phase: Mapped[str] = mapped_column(String(30))  # recon | ...
    tool: Mapped[str] = mapped_column(String(50))
    binary: Mapped[str | None] = mapped_column(String(100), nullable=True)
    version: Mapped[str | None] = mapped_column(String(50), nullable=True)
    command: Mapped[str] = mapped_column(String(4000), default="")
    # ok | failed | timed_out | stopped | cancelled | not_installed | skipped
    status: Mapped[str] = mapped_column(String(20))
    skip_reason: Mapped[str | None] = mapped_column(String(500), nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    exit_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    timed_out: Mapped[bool] = mapped_column(Boolean, default=False)
    results_count: Mapped[int] = mapped_column(Integer, default=0)
    stdout: Mapped[str] = mapped_column(Text, default="")
    stderr: Mapped[str] = mapped_column(Text, default="")
    stdout_truncated: Mapped[bool] = mapped_column(Boolean, default=False)
    stderr_truncated: Mapped[bool] = mapped_column(Boolean, default=False)
