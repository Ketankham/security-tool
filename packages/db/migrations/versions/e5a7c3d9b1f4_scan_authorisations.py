"""scan authorisations + scans.requested_by

Revision ID: e5a7c3d9b1f4
Revises: d4e9a1b6c3f2
Create Date: 2026-11-25 10:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "e5a7c3d9b1f4"
down_revision: str | None = "d4e9a1b6c3f2"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "scan_authorisations",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("scan_id", sa.UUID(), nullable=False),
        sa.Column("target_id", sa.UUID(), nullable=False),
        sa.Column("username", sa.String(length=64), nullable=False),
        sa.Column("accepted_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("statement_version", sa.String(length=20), nullable=False),
        sa.Column("statement_text", sa.String(length=2000), nullable=False),
        sa.Column("client_name", sa.String(length=200), nullable=False),
        sa.Column("target_name", sa.String(length=255), nullable=False),
        sa.Column("tools", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("all_ports_confirmed", sa.Boolean(), nullable=False),
        sa.Column("target_environment", sa.String(length=20), nullable=False),
        sa.Column("options_snapshot", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("client_ip", sa.String(length=64), nullable=True),
        sa.Column("user_agent", sa.String(length=300), nullable=True),
        sa.Column("carried_over_from_scan_id", sa.UUID(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["target_id"], ["targets.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["carried_over_from_scan_id"], ["scans.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_scan_authorisations_scan_id"), "scan_authorisations", ["scan_id"], unique=True
    )
    op.create_index(
        op.f("ix_scan_authorisations_target_id"), "scan_authorisations", ["target_id"], unique=False
    )
    op.add_column("scans", sa.Column("requested_by", sa.String(length=64), nullable=True))


def downgrade() -> None:
    op.drop_column("scans", "requested_by")
    op.drop_index(op.f("ix_scan_authorisations_target_id"), table_name="scan_authorisations")
    op.drop_index(op.f("ix_scan_authorisations_scan_id"), table_name="scan_authorisations")
    op.drop_table("scan_authorisations")
