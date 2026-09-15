from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, DateTime, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ..base import Base, TimestampMixin, UUIDPrimaryKeyMixin
from ..enums import OwnershipVerificationMethod

if TYPE_CHECKING:
    from .organization import Organization
    from .persona import Persona
    from .scan import Scan, ScanPolicy


class Target(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """A domain/application the organization has asked us to test.
    See docs/06-safety-legal-abuse.md §1 — ownership_verified gates every
    authenticated or active scan, no exceptions."""

    __tablename__ = "targets"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), index=True
    )
    root_domain: Mapped[str] = mapped_column(String(255), index=True)
    display_name: Mapped[str] = mapped_column(String(200))
    is_production: Mapped[bool] = mapped_column(Boolean, default=True)

    ownership_verified: Mapped[bool] = mapped_column(Boolean, default=False)
    ownership_verification_method: Mapped[OwnershipVerificationMethod | None] = mapped_column(
        nullable=True
    )
    ownership_verification_token: Mapped[str | None] = mapped_column(String(200), nullable=True)
    ownership_verified_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    authorization_accepted: Mapped[bool] = mapped_column(Boolean, default=False)
    authorization_accepted_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    authorization_accepted_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id"), nullable=True
    )

    organization: Mapped[Organization] = relationship(back_populates="targets")
    scope_rules: Mapped[list[ScopeRule]] = relationship(
        back_populates="target", cascade="all, delete-orphan"
    )
    personas: Mapped[list[Persona]] = relationship(
        back_populates="target", cascade="all, delete-orphan"
    )
    scan_policy: Mapped[ScanPolicy | None] = relationship(
        back_populates="target", uselist=False, cascade="all, delete-orphan"
    )
    scans: Mapped[list[Scan]] = relationship(back_populates="target", cascade="all, delete-orphan")

    @property
    def is_scannable(self) -> bool:
        """The one-line gate the API and worker both check before letting
        anything past QUEUED (docs/06 §1)."""
        return self.ownership_verified and self.authorization_accepted


class ScopeRule(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Persisted form of sentinel_core.scope_guard.ScopeRule — the DB is the
    source of truth; the ScopeGuard is instantiated from these rows at the
    start of every scan (and re-checked, not just trusted, per request)."""

    __tablename__ = "scope_rules"

    target_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("targets.id", ondelete="CASCADE"), index=True
    )
    kind: Mapped[str] = mapped_column(String(20))  # host | path_prefix | path_regex | method
    pattern: Mapped[str] = mapped_column(String(500))
    effect: Mapped[str] = mapped_column(String(10))  # include | exclude
    label: Mapped[str] = mapped_column(String(200), default="")

    target: Mapped[Target] = relationship(back_populates="scope_rules")
