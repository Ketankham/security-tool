"""recon tool runs + asset sources / scope status

Revision ID: d4e9a1b6c3f2
Revises: c3a8f5d2e7b1
Create Date: 2026-11-18 15:30:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "d4e9a1b6c3f2"
down_revision: str | None = "c3a8f5d2e7b1"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "tool_runs",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("scan_id", sa.UUID(), nullable=False),
        sa.Column("seq", sa.Integer(), nullable=False),
        sa.Column("phase", sa.String(length=30), nullable=False),
        sa.Column("tool", sa.String(length=50), nullable=False),
        sa.Column("binary", sa.String(length=100), nullable=True),
        sa.Column("version", sa.String(length=50), nullable=True),
        sa.Column("command", sa.String(length=4000), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("skip_reason", sa.String(length=500), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("duration_ms", sa.Integer(), nullable=True),
        sa.Column("exit_code", sa.Integer(), nullable=True),
        sa.Column("timed_out", sa.Boolean(), nullable=False),
        sa.Column("results_count", sa.Integer(), nullable=False),
        sa.Column("stdout", sa.Text(), nullable=False),
        sa.Column("stderr", sa.Text(), nullable=False),
        sa.Column("stdout_truncated", sa.Boolean(), nullable=False),
        sa.Column("stderr_truncated", sa.Boolean(), nullable=False),
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
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_tool_runs_scan_id"), "tool_runs", ["scan_id"], unique=False)
    op.add_column(
        "assets",
        sa.Column(
            "sources",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'[]'::jsonb"),
            nullable=False,
        ),
    )
    op.add_column(
        "assets",
        sa.Column("scope_status", sa.String(length=30), server_default="in_scope", nullable=False),
    )
    op.add_column("assets", sa.Column("scope_reason", sa.String(length=500), nullable=True))


def downgrade() -> None:
    op.drop_column("assets", "scope_reason")
    op.drop_column("assets", "scope_status")
    op.drop_column("assets", "sources")
    op.drop_index(op.f("ix_tool_runs_scan_id"), table_name="tool_runs")
    op.drop_table("tool_runs")
