"""Add host_package_updates.is_security

Revision ID: 20260205_01
Revises: 20260205_00
Create Date: 2026-02-05

"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "20260205_01"
down_revision = "20260205_00"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    dialect = bind.dialect.name

    if dialect == "postgresql":
        op.execute("ALTER TABLE host_package_updates ADD COLUMN IF NOT EXISTS is_security boolean NOT NULL DEFAULT false")
        op.execute("CREATE INDEX IF NOT EXISTS ix_host_package_updates_is_security ON host_package_updates (is_security)")
    else:
        try:
            op.add_column(
                "host_package_updates",
                sa.Column("is_security", sa.Boolean(), nullable=False, server_default=sa.text("0")),
            )
        except Exception:
            pass


def downgrade() -> None:
    pass
