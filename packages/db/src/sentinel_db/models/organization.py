from __future__ import annotations

import uuid
from typing import TYPE_CHECKING

from sqlalchemy import ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ..base import Base, TimestampMixin, UUIDPrimaryKeyMixin
from ..enums import OrgRole

if TYPE_CHECKING:
    from .target import Target


class Organization(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "organizations"

    name: Mapped[str] = mapped_column(String(200))
    slug: Mapped[str] = mapped_column(String(200), unique=True, index=True)

    # Envelope encryption (docs/01 §6.3): the org's data key, generated once,
    # wrapped by the platform's master key (KMS in prod). Never the raw key.
    wrapped_data_key: Mapped[bytes] = mapped_column()

    stripe_customer_id: Mapped[str | None] = mapped_column(String(100), nullable=True)
    stripe_subscription_id: Mapped[str | None] = mapped_column(String(100), nullable=True)
    plan: Mapped[str] = mapped_column(String(50), default="free_scan")

    users: Mapped[list[User]] = relationship(
        back_populates="organization", cascade="all, delete-orphan"
    )
    targets: Mapped[list[Target]] = relationship(
        back_populates="organization", cascade="all, delete-orphan"
    )


class User(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "users"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), index=True
    )
    clerk_user_id: Mapped[str] = mapped_column(String(200), unique=True, index=True)
    email: Mapped[str] = mapped_column(String(320))
    role: Mapped[OrgRole] = mapped_column(default=OrgRole.MEMBER)

    organization: Mapped[Organization] = relationship(back_populates="users")
