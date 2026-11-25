"""discovered paths (directory brute force results)

Revision ID: f6b8d4e0c2a5
Revises: e5a7c3d9b1f4
Create Date: 2026-11-25 14:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "f6b8d4e0c2a5"
down_revision: str | None = "e5a7c3d9b1f4"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "discovered_paths",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("scan_id", sa.UUID(), nullable=False),
        sa.Column("tool_run_id", sa.UUID(), nullable=True),
        sa.Column("origin", sa.String(length=300), nullable=False),
        sa.Column("path", sa.String(length=1000), nullable=False),
        sa.Column("url", sa.String(length=2000), nullable=False),
        sa.Column("method", sa.String(length=10), nullable=False),
        sa.Column("status_code", sa.Integer(), nullable=False),
        sa.Column("content_length", sa.Integer(), nullable=True),
        sa.Column("words", sa.Integer(), nullable=True),
        sa.Column("lines", sa.Integer(), nullable=True),
        sa.Column("content_type", sa.String(length=200), nullable=True),
        sa.Column("redirect_location", sa.String(length=2000), nullable=True),
        sa.Column("category", sa.String(length=20), nullable=False),
        sa.Column("wordlist", sa.String(length=50), nullable=False),
        sa.Column("verdict", sa.String(length=20), nullable=False),
        sa.Column("rule_id", sa.String(length=100), nullable=True),
        sa.Column("finding_id", sa.UUID(), nullable=True),
        sa.Column("note", sa.String(length=500), nullable=True),
        sa.Column("crawl_seed", sa.Boolean(), server_default=sa.text("false"), nullable=False),
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
        sa.ForeignKeyConstraint(["tool_run_id"], ["tool_runs.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["finding_id"], ["findings.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_discovered_paths_scan_id"), "discovered_paths", ["scan_id"])


def downgrade() -> None:
    op.drop_index(op.f("ix_discovered_paths_scan_id"), table_name="discovered_paths")
    op.drop_table("discovered_paths")
