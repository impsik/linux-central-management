"""add cve severity fields for reporting

Revision ID: 20260505_00
Revises: 20260420_00
Create Date: 2026-05-05
"""

from alembic import op
import sqlalchemy as sa


revision = "20260505_00"
down_revision = "20260420_00"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("cve_definitions", sa.Column("severity", sa.String(), nullable=True))
    op.add_column("cve_packages", sa.Column("severity", sa.String(), nullable=True))


def downgrade() -> None:
    op.drop_column("cve_packages", "severity")
    op.drop_column("cve_definitions", "severity")
