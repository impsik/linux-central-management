"""add job run nonce

Revision ID: 20260621_01
Revises: 20260621_00
Create Date: 2026-06-21
"""

from alembic import op
import sqlalchemy as sa


revision = "20260621_01"
down_revision = "20260621_00"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("job_runs", sa.Column("job_nonce", sa.String(), nullable=True))
    op.create_index("ix_job_runs_job_nonce", "job_runs", ["job_nonce"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_job_runs_job_nonce", table_name="job_runs")
    op.drop_column("job_runs", "job_nonce")
