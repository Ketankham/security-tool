"""port services (port scan results) and a second output for tool runs

Revision ID: a7c9e5f1d3b6
Revises: f6b8d4e0c2a5
Create Date: 2026-11-25 16:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "a7c9e5f1d3b6"
down_revision: str | None = "f6b8d4e0c2a5"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "port_services",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("scan_id", sa.UUID(), nullable=False),
        sa.Column("tool_run_id", sa.UUID(), nullable=True),
        sa.Column("ip", sa.String(length=64), nullable=False),
        sa.Column("hosts", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("port", sa.Integer(), nullable=False),
        sa.Column("protocol", sa.String(length=10), nullable=False),
        sa.Column("state", sa.String(length=20), nullable=False),
        sa.Column("service", sa.String(length=100), nullable=True),
        sa.Column("product", sa.String(length=200), nullable=True),
        sa.Column("version", sa.String(length=100), nullable=True),
        sa.Column("extra_info", sa.String(length=300), nullable=True),
        sa.Column("confidence", sa.String(length=20), nullable=False),
        sa.Column("scripts", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("cdn", sa.String(length=100), nullable=True),
        sa.Column("found_by", sa.String(length=20), nullable=False),
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
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "scan_id", "ip", "port", "protocol", name="uq_port_services_scan_ip_port"
        ),
    )
    op.create_index(op.f("ix_port_services_scan_id"), "port_services", ["scan_id"])
    op.add_column(
        "tool_runs",
        sa.Column("extra_output", sa.Text(), server_default=sa.text("''"), nullable=False),
    )
    op.add_column("tool_runs", sa.Column("extra_output_label", sa.String(length=50), nullable=True))


def downgrade() -> None:
    op.drop_column("tool_runs", "extra_output_label")
    op.drop_column("tool_runs", "extra_output")
    op.drop_index(op.f("ix_port_services_scan_id"), table_name="port_services")
    op.drop_table("port_services")
