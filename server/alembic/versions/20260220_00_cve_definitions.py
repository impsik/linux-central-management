"""add cve_definitions table

Revision ID: 20260220_00
Revises: 20260219_00
Create Date: 2026-02-20
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision = "20260220_00"
down_revision = "20260219_00"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "cve_definitions",
        sa.Column("cve_id", sa.String(), nullable=False),
        sa.Column("definition_data", sa.JSON(), nullable=False, server_default=sa.text("'{}'::json")),
        sa.Column("last_updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.PrimaryKeyConstraint("cve_id"),
    )


def downgrade() -> None:
    op.drop_table("cve_definitions")
