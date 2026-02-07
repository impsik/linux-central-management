"""Add patch_campaigns.include_kernel

Revision ID: 20260205_02
Revises: 20260205_01
Create Date: 2026-02-05

"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "20260205_02"
down_revision = "20260205_01"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    dialect = bind.dialect.name

    if dialect == "postgresql":
        op.execute("ALTER TABLE patch_campaigns ADD COLUMN IF NOT EXISTS include_kernel boolean NOT NULL DEFAULT false")
        op.execute("CREATE INDEX IF NOT EXISTS ix_patch_campaigns_include_kernel ON patch_campaigns (include_kernel)")
    else:
        try:
            op.add_column(
                "patch_campaigns",
                sa.Column("include_kernel", sa.Boolean(), nullable=False, server_default=sa.text("0")),
            )
        except Exception:
            pass


def downgrade() -> None:
    pass
