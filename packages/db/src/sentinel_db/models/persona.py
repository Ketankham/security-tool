"""Persona + Credential.

Persona is the entity that makes multi-role authorization testing possible
at all (docs/01-architecture.md §6.2): trust_rank and tenant_key together
generate the entire authz replay matrix (docs/03 §4.2). Credential is kept
as its own table, separately encrypted, so a Persona row can be freely
logged/displayed/joined without ever touching the secret.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, ForeignKey, Integer, LargeBinary, String
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ..base import Base, TimestampMixin, UUIDPrimaryKeyMixin
from ..enums import CredentialKind, LoginStrategy

if TYPE_CHECKING:
    from .target import Target


class Credential(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Envelope-encrypted secret material for one persona. Decrypted only
    in-memory inside a scanner worker (docs/01 §6.3 rule 2); never logged,
    never included in an LLM prompt (rule 3, enforced in sentinel_ai)."""

    __tablename__ = "credentials"

    kind: Mapped[CredentialKind]
    ciphertext: Mapped[bytes] = mapped_column(LargeBinary)  # Fernet(org data key).encrypt(secret)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class Persona(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "personas"

    target_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("targets.id", ondelete="CASCADE"), index=True
    )
    label: Mapped[str] = mapped_column(String(200))  # "Acme admin"
    role_name: Mapped[str] = mapped_column(String(100))  # customer's own name for the role

    trust_rank: Mapped[int] = mapped_column(Integer, default=0)  # 0 = anonymous
    tenant_key: Mapped[str | None] = mapped_column(String(200), nullable=True, index=True)

    credential_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("credentials.id"), nullable=True
    )
    login_strategy: Mapped[LoginStrategy | None] = mapped_column(nullable=True)

    # LoginRecipe (docs/01 §6.4), recorded once, replayed every scan.
    login_recipe: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    login_recipe_version: Mapped[int] = mapped_column(Integer, default=1)

    # Playwright storage_state, itself envelope-encrypted; short TTL.
    session_state_ciphertext: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    session_state_updated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    session_state_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Session oracle (docs/01 §6.5): how we cheaply confirm this persona's
    # session is still alive before trusting any authz verdict about it.
    session_oracle: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    canary_tokens: Mapped[list[str]] = mapped_column(JSONB, default=list)
    expected_denied: Mapped[list[str]] = mapped_column(JSONB, default=list)

    is_available: Mapped[bool] = mapped_column(default=True)  # False if login/oracle setup failed
    unavailable_reason: Mapped[str | None] = mapped_column(String(500), nullable=True)

    target: Mapped[Target] = relationship(back_populates="personas")
    credential: Mapped[Credential | None] = relationship()
