"""add job run retry count

Revision ID: 20260710_00
Revises: 20260621_02
Create Date: 2026-07-10
"""

from alembic import op
import sqlalchemy as sa


revision = "20260710_00"
down_revision = "20260621_02"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("job_runs", sa.Column("retry_count", sa.Integer(), nullable=False, server_default="0"))
    op.alter_column("job_runs", "retry_count", server_default=None)


def downgrade() -> None:
    op.drop_column("job_runs", "retry_count")
