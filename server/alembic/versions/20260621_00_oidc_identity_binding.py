"""add oidc identity binding columns

Revision ID: 20260621_00
Revises: 20260619_00
Create Date: 2026-06-21
"""

from alembic import op
import sqlalchemy as sa


revision = "20260621_00"
down_revision = "20260619_00"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("app_users", sa.Column("oidc_issuer", sa.String(), nullable=True))
    op.add_column("app_users", sa.Column("oidc_subject", sa.String(), nullable=True))
    op.create_index("ix_app_users_oidc_issuer", "app_users", ["oidc_issuer"], unique=False)
    op.create_index("ix_app_users_oidc_subject", "app_users", ["oidc_subject"], unique=False)
    op.create_unique_constraint("uq_app_users_oidc_identity", "app_users", ["oidc_issuer", "oidc_subject"])


def downgrade() -> None:
    op.drop_constraint("uq_app_users_oidc_identity", "app_users", type_="unique")
    op.drop_index("ix_app_users_oidc_subject", table_name="app_users")
    op.drop_index("ix_app_users_oidc_issuer", table_name="app_users")
    op.drop_column("app_users", "oidc_subject")
    op.drop_column("app_users", "oidc_issuer")
