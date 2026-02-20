"""add cve_packages table

Revision ID: 20260221_00
Revises: 20260220_00
Create Date: 2026-02-21
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision = "20260221_00"
down_revision = "20260220_00"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "cve_packages",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("cve_id", sa.String(), nullable=False),
        sa.Column("package_name", sa.String(), nullable=False),
        sa.Column("release", sa.String(), nullable=False),
        sa.Column("fixed_version", sa.String(), nullable=False),
        sa.Column("status", sa.String(), nullable=False, server_default="unknown"),
        sa.ForeignKeyConstraint(["cve_id"], ["cve_definitions.cve_id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_cve_packages_cve_id", "cve_packages", ["cve_id"], unique=False)
    op.create_index("ix_cve_packages_package_name", "cve_packages", ["package_name"], unique=False)
    op.create_index("ix_cve_packages_release", "cve_packages", ["release"], unique=False)
    op.create_index("ix_cve_packages_lookup", "cve_packages", ["release", "package_name"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_cve_packages_lookup", table_name="cve_packages")
    op.drop_index("ix_cve_packages_release", table_name="cve_packages")
    op.drop_index("ix_cve_packages_package_name", table_name="cve_packages")
    op.drop_index("ix_cve_packages_cve_id", table_name="cve_packages")
    op.drop_table("cve_packages")
