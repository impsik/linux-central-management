"""host metrics snapshots table

Revision ID: 20260419_00
Revises: 20260414_00
Create Date: 2026-04-19
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "20260419_00"
down_revision = "20260414_00"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "host_metrics_snapshots",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("agent_id", sa.String(), nullable=False),
        sa.Column("disk_percent_used", sa.String(), nullable=True),
        sa.Column("mem_percent_used", sa.String(), nullable=True),
        sa.Column("load_1min", sa.String(), nullable=True),
        sa.Column("vcpus", sa.Integer(), nullable=True),
        sa.Column("recorded_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_host_metrics_snapshots_agent_id", "host_metrics_snapshots", ["agent_id"])
    op.create_index("ix_host_metrics_snapshots_recorded_at", "host_metrics_snapshots", ["recorded_at"])
    op.create_index(
        "ix_host_metrics_snapshots_agent_recorded",
        "host_metrics_snapshots",
        ["agent_id", "recorded_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_host_metrics_snapshots_agent_recorded", table_name="host_metrics_snapshots")
    op.drop_index("ix_host_metrics_snapshots_recorded_at", table_name="host_metrics_snapshots")
    op.drop_index("ix_host_metrics_snapshots_agent_id", table_name="host_metrics_snapshots")
    op.drop_table("host_metrics_snapshots")
