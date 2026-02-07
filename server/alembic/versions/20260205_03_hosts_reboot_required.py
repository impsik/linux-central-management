"""Add hosts.reboot_required

Revision ID: 20260205_03
Revises: 20260205_02
Create Date: 2026-02-05

"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "20260205_03"
down_revision = "20260205_02"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    dialect = bind.dialect.name

    if dialect == "postgresql":
        op.execute("ALTER TABLE hosts ADD COLUMN IF NOT EXISTS reboot_required boolean NOT NULL DEFAULT false")
        op.execute("CREATE INDEX IF NOT EXISTS ix_hosts_reboot_required ON hosts (reboot_required)")
    else:
        try:
            op.add_column(
                "hosts",
                sa.Column("reboot_required", sa.Boolean(), nullable=False, server_default=sa.text("0")),
            )
        except Exception:
            pass


def downgrade() -> None:
    pass
