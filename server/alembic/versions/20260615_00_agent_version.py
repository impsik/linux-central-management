"""add agent version to hosts

Revision ID: 20260615_00
Revises: 20260505_01
Create Date: 2026-06-15
"""

from alembic import op
import sqlalchemy as sa


revision = "20260615_00"
down_revision = "20260505_01"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("hosts", sa.Column("agent_version", sa.String(), nullable=True))


def downgrade() -> None:
    op.drop_column("hosts", "agent_version")
