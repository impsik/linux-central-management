"""add missing host_cve_status table

Revision ID: 20260408_02
Revises: 20260408_01
Create Date: 2026-04-08
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "20260408_02"
down_revision = "20260408_01"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    dialect = bind.dialect.name

    uuid_t = postgresql.UUID(as_uuid=True) if dialect == "postgresql" else sa.String(length=36)
    json_t = postgresql.JSONB(astext_type=sa.Text()) if dialect == "postgresql" else sa.JSON()

    op.create_table(
        "host_cve_status",
        sa.Column("host_id", uuid_t, sa.ForeignKey("hosts.id", ondelete="CASCADE"), primary_key=True, nullable=False),
        sa.Column("cve", sa.String(), primary_key=True, nullable=False),
        sa.Column("package_name", sa.String(), nullable=False),
        sa.Column("installed_version", sa.String(), nullable=False),
        sa.Column("fixed_version", sa.String(), nullable=False),
        sa.Column("release", sa.String(), nullable=False),
        sa.Column("status", sa.String(), nullable=False, server_default="unknown"),
        sa.Column("affected", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("detail", json_t, nullable=False),
        sa.Column("checked_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_host_cve_status_host_id", "host_cve_status", ["host_id"])
    op.create_index("ix_host_cve_status_cve", "host_cve_status", ["cve"])
    op.create_index("ix_host_cve_status_cve_affected", "host_cve_status", ["cve", "affected"])


def downgrade() -> None:
    op.drop_index("ix_host_cve_status_cve_affected", table_name="host_cve_status")
    op.drop_index("ix_host_cve_status_cve", table_name="host_cve_status")
    op.drop_index("ix_host_cve_status_host_id", table_name="host_cve_status")
    op.drop_table("host_cve_status")
