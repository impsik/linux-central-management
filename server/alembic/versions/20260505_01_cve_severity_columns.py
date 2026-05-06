"""compatibility no-op for duplicate cve severity migration

Revision ID: 20260505_01
Revises: 20260505_00
Create Date: 2026-05-05
"""

revision = "20260505_01"
down_revision = "20260505_00"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # 20260505_00 already adds these columns.  This revision is kept so any
    # database that has seen the duplicate revision id remains understandable to
    # Alembic, while new upgrades have a single linear head.
    pass


def downgrade() -> None:
    # Keep downgrade non-destructive here; dropping belongs to 20260505_00.
    pass
