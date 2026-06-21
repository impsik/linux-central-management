"""add host agent token hash

Revision ID: 20260621_02
Revises: 20260621_01
Create Date: 2026-06-21
"""

from alembic import op
import sqlalchemy as sa


revision = "20260621_02"
down_revision = "20260621_01"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("hosts", sa.Column("agent_token_hash", sa.String(), nullable=True))
    op.create_index("ix_hosts_agent_token_hash", "hosts", ["agent_token_hash"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_hosts_agent_token_hash", table_name="hosts")
    op.drop_column("hosts", "agent_token_hash")
