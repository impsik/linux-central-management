"""patch campaigns rollout meta

Revision ID: 20260225_02
Revises: 20260225_01
Create Date: 2026-02-25
"""

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "20260225_02"
down_revision = "20260225_01"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "patch_campaigns",
        sa.Column("rollout_meta", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
    )


def downgrade() -> None:
    op.drop_column("patch_campaigns", "rollout_meta")
