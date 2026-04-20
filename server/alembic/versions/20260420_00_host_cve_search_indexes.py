"""add host cve search indexes

Revision ID: 20260420_00
Revises: 20260419_01
Create Date: 2026-04-20
"""

from alembic import op


revision = "20260420_00"
down_revision = "20260419_01"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("CREATE INDEX IF NOT EXISTS ix_host_cve_status_cve ON host_cve_status (cve)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_host_cve_status_cve_affected ON host_cve_status (cve, affected)")


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ix_host_cve_status_cve_affected")
    op.execute("DROP INDEX IF EXISTS ix_host_cve_status_cve")
