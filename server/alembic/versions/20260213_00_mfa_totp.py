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


def _columns(table_name: str) -> set[str]:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if not inspector.has_table(table_name):
        return set()
    return {column["name"] for column in inspector.get_columns(table_name)}


def _add_column_if_missing(table_name: str, existing_columns: set[str], column: sa.Column) -> None:
    if column.name in existing_columns:
        return
    op.add_column(table_name, column)
    existing_columns.add(column.name)


def upgrade() -> None:
    app_user_columns = _columns("app_users")
    app_session_columns = _columns("app_sessions")

    _add_column_if_missing(
        "app_users",
        app_user_columns,
        sa.Column("mfa_enabled", sa.Boolean(), nullable=False, server_default=sa.text("false")),
    )
    _add_column_if_missing("app_users", app_user_columns, sa.Column("totp_secret_enc", sa.Text(), nullable=True))
    _add_column_if_missing(
        "app_users",
        app_user_columns,
        sa.Column("totp_secret_pending_enc", sa.Text(), nullable=True),
    )
    _add_column_if_missing(
        "app_users",
        app_user_columns,
        sa.Column("mfa_enrolled_at", sa.DateTime(timezone=True), nullable=True),
    )
    _add_column_if_missing(
        "app_users",
        app_user_columns,
        sa.Column("mfa_pending_at", sa.DateTime(timezone=True), nullable=True),
    )
    _add_column_if_missing(
        "app_users",
        app_user_columns,
        sa.Column("recovery_codes", sa.JSON(), nullable=False, server_default=sa.text("'[]'::json")),
    )

    _add_column_if_missing(
        "app_sessions",
        app_session_columns,
        sa.Column("mfa_verified_at", sa.DateTime(timezone=True), nullable=True),
    )

    # cleanup defaults
    if "mfa_enabled" in app_user_columns:
        op.alter_column("app_users", "mfa_enabled", server_default=None)
    if "recovery_codes" in app_user_columns:
        op.alter_column("app_users", "recovery_codes", server_default=None)


def downgrade() -> None:
    op.drop_column("app_sessions", "mfa_verified_at")

    op.drop_column("app_users", "recovery_codes")
    op.drop_column("app_users", "mfa_pending_at")
    op.drop_column("app_users", "mfa_enrolled_at")
    op.drop_column("app_users", "totp_secret_pending_enc")
    op.drop_column("app_users", "totp_secret_enc")
    op.drop_column("app_users", "mfa_enabled")
