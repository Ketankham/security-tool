"""DiscoveredPath: one path found by directory/file brute force (ffuf, plus the
built-in HEAD pass for archives), with what the host answered and what we
concluded.

``verdict``:
  confirmed      a known file signature matched and re-checking twice reproduced
                 it; ``finding_id`` points at the Finding
  not_confirmed  answered, matched a signature once or looked like one, but did
                 not hold up on re-check (``note`` says why)
  found          answered with something that was not the host's default answer;
                 no file signature to check it against

Only names, status, size and type are stored. The body of a file that may hold
secrets (a .env, a Git config) is never fetched into storage.
"""

from __future__ import annotations

import uuid

from sqlalchemy import Boolean, ForeignKey, Integer, String, text
from sqlalchemy.orm import Mapped, mapped_column

from ..base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class DiscoveredPath(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "discovered_paths"

    scan_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), index=True
    )
    tool_run_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("tool_runs.id", ondelete="SET NULL"), nullable=True
    )
    # scheme://host[:port] as the site is known (never the pinned IP).
    origin: Mapped[str] = mapped_column(String(300))
    path: Mapped[str] = mapped_column(String(1000))  # "/.env"
    url: Mapped[str] = mapped_column(String(2000))
    method: Mapped[str] = mapped_column(String(10))  # GET | HEAD
    status_code: Mapped[int] = mapped_column(Integer)
    content_length: Mapped[int | None] = mapped_column(Integer, nullable=True)
    words: Mapped[int | None] = mapped_column(Integer, nullable=True)
    lines: Mapped[int | None] = mapped_column(Integer, nullable=True)
    content_type: Mapped[str | None] = mapped_column(String(200), nullable=True)
    redirect_location: Mapped[str | None] = mapped_column(String(2000), nullable=True)
    # config | backup | vcs | admin | api | common (the wordlist entry's category)
    category: Mapped[str] = mapped_column(String(20))
    wordlist: Mapped[str] = mapped_column(String(50))
    verdict: Mapped[str] = mapped_column(String(20))  # confirmed | not_confirmed | found
    rule_id: Mapped[str | None] = mapped_column(String(100), nullable=True)
    finding_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("findings.id", ondelete="SET NULL"), nullable=True
    )
    note: Mapped[str | None] = mapped_column(String(500), nullable=True)
    # Offered to the crawler as a start page.
    crawl_seed: Mapped[bool] = mapped_column(Boolean, default=False, server_default=text("false"))
