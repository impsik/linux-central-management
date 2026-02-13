"""MFA TOTP support

Revision ID: 20260213_00
Revises: 20260205_03
Create Date: 2026-02-13

"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = "20260213_00"
down_revision = "20260205_03"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("app_users", sa.Column("mfa_enabled", sa.Boolean(), nullable=False, server_default=sa.text("false")))
    op.add_column("app_users", sa.Column("totp_secret_enc", sa.Text(), nullable=True))
    op.add_column("app_users", sa.Column("totp_secret_pending_enc", sa.Text(), nullable=True))
    op.add_column("app_users", sa.Column("mfa_enrolled_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("app_users", sa.Column("mfa_pending_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("app_users", sa.Column("recovery_codes", sa.JSON(), nullable=False, server_default=sa.text("'[]'::json")))

    op.add_column("app_sessions", sa.Column("mfa_verified_at", sa.DateTime(timezone=True), nullable=True))

    # cleanup defaults
    op.alter_column("app_users", "mfa_enabled", server_default=None)
    op.alter_column("app_users", "recovery_codes", server_default=None)


def downgrade() -> None:
    op.drop_column("app_sessions", "mfa_verified_at")

    op.drop_column("app_users", "recovery_codes")
    op.drop_column("app_users", "mfa_pending_at")
    op.drop_column("app_users", "mfa_enrolled_at")
    op.drop_column("app_users", "totp_secret_pending_enc")
    op.drop_column("app_users", "totp_secret_enc")
    op.drop_column("app_users", "mfa_enabled")
