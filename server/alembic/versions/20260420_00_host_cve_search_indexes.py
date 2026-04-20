"""repair host cve status schema and add search indexes

Revision ID: 20260420_00
Revises: 20260419_01
Create Date: 2026-04-20
"""

from alembic import op
import sqlalchemy as sa


revision = "20260420_00"
down_revision = "20260419_01"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    columns = {col["name"] for col in inspector.get_columns("host_cve_status")}

    if "affected" not in columns:
        op.add_column(
            "host_cve_status",
            sa.Column("affected", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        )
        if "status" in columns:
            op.execute(
                "UPDATE host_cve_status SET affected = CASE "
                "WHEN lower(coalesce(status, '')) IN ('open', 'affected', 'vulnerable', 'needed', 'unfixed') THEN true "
                "ELSE false END"
            )
        op.alter_column("host_cve_status", "affected", server_default=None)

    if "summary" not in columns:
        op.add_column("host_cve_status", sa.Column("summary", sa.String(), nullable=True))

    if "checked_at" not in columns:
        op.add_column(
            "host_cve_status",
            sa.Column("checked_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        )
        if "updated_at" in columns:
            op.execute("UPDATE host_cve_status SET checked_at = coalesce(updated_at, checked_at)")
        elif "first_seen_at" in columns:
            op.execute("UPDATE host_cve_status SET checked_at = coalesce(first_seen_at, checked_at)")
        op.alter_column("host_cve_status", "checked_at", server_default=None)

    if "raw" not in columns:
        op.add_column("host_cve_status", sa.Column("raw", sa.Text(), nullable=True))

    op.execute("CREATE INDEX IF NOT EXISTS ix_host_cve_status_host_id ON host_cve_status (host_id)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_host_cve_status_checked_at ON host_cve_status (checked_at)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_host_cve_status_cve ON host_cve_status (cve)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_host_cve_status_cve_affected ON host_cve_status (cve, affected)")


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ix_host_cve_status_cve_affected")
    op.execute("DROP INDEX IF EXISTS ix_host_cve_status_cve")
    op.execute("DROP INDEX IF EXISTS ix_host_cve_status_checked_at")
    op.execute("DROP INDEX IF EXISTS ix_host_cve_status_host_id")
