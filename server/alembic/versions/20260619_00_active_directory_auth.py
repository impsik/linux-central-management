"""add active directory auth settings

Revision ID: 20260619_00
Revises: 20260615_00
Create Date: 2026-06-19
"""

from alembic import op
import sqlalchemy as sa


revision = "20260619_00"
down_revision = "20260615_00"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("app_users", sa.Column("auth_provider", sa.String(), nullable=False, server_default="local"))
    op.create_index("ix_app_users_auth_provider", "app_users", ["auth_provider"], unique=False)
    op.alter_column("app_users", "auth_provider", server_default=None)

    op.create_table(
        "app_auth_settings",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("ad_enabled", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("ad_server_uri", sa.String(), nullable=True),
        sa.Column("ad_domain", sa.String(), nullable=True),
        sa.Column("ad_base_dn", sa.String(), nullable=True),
        sa.Column("ad_bind_dn", sa.String(), nullable=True),
        sa.Column("ad_bind_password_enc", sa.Text(), nullable=True),
        sa.Column("ad_user_filter", sa.String(), nullable=False, server_default="(sAMAccountName={username})"),
        sa.Column("ad_use_ssl", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("ad_role", sa.String(), nullable=False, server_default="operator"),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.execute("INSERT INTO app_auth_settings (id) VALUES (1) ON CONFLICT (id) DO NOTHING")
    op.alter_column("app_auth_settings", "ad_enabled", server_default=None)
    op.alter_column("app_auth_settings", "ad_user_filter", server_default=None)
    op.alter_column("app_auth_settings", "ad_use_ssl", server_default=None)
    op.alter_column("app_auth_settings", "ad_role", server_default=None)


def downgrade() -> None:
    op.drop_table("app_auth_settings")
    op.drop_index("ix_app_users_auth_provider", table_name="app_users")
    op.drop_column("app_users", "auth_provider")
