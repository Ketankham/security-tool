"""Asset / Endpoint / Parameter — the surface map (docs/02-scan-lifecycle.md
Phase 1 & 3). Endpoint.discovered_by_persona_ids is what makes the
per-persona surface diff (docs/00 §3 step 4) a cheap query rather than a
re-crawl."""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING

from sqlalchemy import ForeignKey, String
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ..base import Base, TimestampMixin, UUIDPrimaryKeyMixin

if TYPE_CHECKING:
    pass


class Asset(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "assets"

    scan_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), index=True
    )
    host: Mapped[str] = mapped_column(String(255), index=True)
    kind: Mapped[str] = mapped_column(
        String(50), default="unknown"
    )  # app | api | admin | marketing | unknown
    tech_fingerprint: Mapped[list[str]] = mapped_column(JSONB, default=list)

    # Populated by Phase 1 recon (sentinel_recon.ReconResult) — resolved IPs
    # and the raw HTTP probe records (status/title/server/tech per URL).
    ip_addresses: Mapped[list[str]] = mapped_column(JSONB, default=list)
    http_probes: Mapped[list[dict]] = mapped_column(JSONB, default=list)
    discovery_source: Mapped[str] = mapped_column(String(30), default="root_domain")

    endpoints: Mapped[list[Endpoint]] = relationship(
        back_populates="asset", cascade="all, delete-orphan"
    )


class Endpoint(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "endpoints"

    asset_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("assets.id", ondelete="CASCADE"), index=True
    )
    method: Mapped[str] = mapped_column(String(10))
    path_template: Mapped[str] = mapped_column(String(1000), index=True)  # "/users/{id}"

    # Personas that reached this endpoint during their own crawl — the raw
    # material for the cross-persona surface diff.
    discovered_by_persona_ids: Mapped[list[str]] = mapped_column(JSONB, default=list)
    discovery_source: Mapped[str] = mapped_column(
        String(30), default="rendered_crawl"
    )  # rendered_crawl | js_extraction | openapi | graphql

    asset: Mapped[Asset] = relationship(back_populates="endpoints")
    parameters: Mapped[list[Parameter]] = relationship(
        back_populates="endpoint", cascade="all, delete-orphan"
    )


class Parameter(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """AI-labelled parameter semantics (docs/02 Phase 3 step 5) — this
    labelling is what *targets* the injection and IDOR phases instead of
    testing every parameter blindly."""

    __tablename__ = "parameters"

    endpoint_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("endpoints.id", ondelete="CASCADE"), index=True
    )
    name: Mapped[str] = mapped_column(String(200))
    location: Mapped[str] = mapped_column(String(20))  # query | body | header | path | cookie
    semantic_label: Mapped[str | None] = mapped_column(String(50), nullable=True)
    # object_reference | tenant_key | role_field | redirect_target
    # | file_path | html_sink | query_filter | unknown
    label_confidence: Mapped[float | None] = mapped_column(nullable=True)

    endpoint: Mapped[Endpoint] = relationship(back_populates="parameters")
