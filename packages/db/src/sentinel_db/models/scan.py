"""ScanPolicy, Scan, ScanPhase — the persisted form of
sentinel_core.state_machine.ScanStateMachine (docs/01 §5)."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sentinel_core.state_machine import PhaseStatus, ScanPhaseName, ScanState
from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ..base import Base, TimestampMixin, UUIDPrimaryKeyMixin
from ..enums import ScanIntensity

if TYPE_CHECKING:
    from .target import Target


class ScanPolicy(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "scan_policies"

    target_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("targets.id", ondelete="CASCADE"), unique=True, index=True
    )
    intensity: Mapped[ScanIntensity] = mapped_column(default=ScanIntensity.STANDARD)
    schedule_cron: Mapped[str | None] = mapped_column(String(100), nullable=True)
    read_write_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    max_requests_per_second: Mapped[float] = mapped_column(default=5.0)
    testing_window_start_hour_utc: Mapped[int | None] = mapped_column(Integer, nullable=True)
    testing_window_end_hour_utc: Mapped[int | None] = mapped_column(Integer, nullable=True)

    target: Mapped[Target] = relationship(back_populates="scan_policy")


class Scan(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "scans"

    target_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("targets.id", ondelete="CASCADE"), index=True
    )
    triggered_by: Mapped[str] = mapped_column(
        String(50), default="manual"
    )  # manual | schedule | api

    state: Mapped[ScanState] = mapped_column(default=ScanState.QUEUED, index=True)
    paused_from: Mapped[ScanState | None] = mapped_column(nullable=True)
    fail_reason: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    is_degraded: Mapped[bool] = mapped_column(Boolean, default=False)
    degraded_reasons: Mapped[list[str]] = mapped_column(JSONB, default=list)

    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # LLM cost control (ADR-0001 §"Consequences", docs/01 §3.4)
    llm_token_budget: Mapped[int] = mapped_column(Integer, default=200_000)
    llm_tokens_used: Mapped[int] = mapped_column(Integer, default=0)

    target: Mapped[Target] = relationship(back_populates="scans")
    phases: Mapped[list[ScanPhase]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )


class ScanPhase(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """One row per phase per scan. Individually resumable (docs/01 §5) — a
    crashed phase restarts from its own stats_json checkpoint, not from
    the beginning of the scan."""

    __tablename__ = "scan_phases"

    scan_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), index=True
    )
    name: Mapped[ScanPhaseName]
    status: Mapped[PhaseStatus] = mapped_column(default=PhaseStatus.PENDING)

    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    error: Mapped[str | None] = mapped_column(String(2000), nullable=True)

    # Free-form per-phase progress/checkpoint/result-summary data, e.g.
    # {"assets_found": 42, "checkpoint_cursor": "...", "tool_versions": {...}}
    stats_json: Mapped[dict] = mapped_column(JSONB, default=dict)

    scan: Mapped[Scan] = relationship(back_populates="phases")
