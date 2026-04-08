"""add app_maintenance_windows table

Revision ID: 20260408_00
Revises: 20260225_02
Create Date: 2026-04-08
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision = "20260408_00"
down_revision = "20260225_02"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    dialect = bind.dialect.name

    if dialect == "postgresql":
        # Compatibility for legacy databases that were created outside Alembic
        # and therefore never got an Alembic migration creating app_saved_views.
        op.execute(
            """
            CREATE TABLE IF NOT EXISTS app_saved_views (
              id uuid PRIMARY KEY,
              user_id uuid NOT NULL REFERENCES app_users(id) ON DELETE CASCADE,
              scope varchar NOT NULL DEFAULT 'hosts',
              name varchar NOT NULL,
              payload json NOT NULL DEFAULT '{}'::json,
              is_shared boolean NOT NULL DEFAULT false,
              is_default_startup boolean NOT NULL DEFAULT false,
              created_at timestamptz NOT NULL DEFAULT now(),
              updated_at timestamptz NOT NULL DEFAULT now()
            )
            """
        )
        op.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS uq_app_saved_views_user_scope_name ON app_saved_views (user_id, scope, name)"
        )
        op.execute(
            "CREATE INDEX IF NOT EXISTS ix_app_saved_views_user_scope ON app_saved_views (user_id, scope)"
        )

    op.create_table(
        "app_maintenance_windows",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("timezone", sa.String(), nullable=False, server_default="UTC"),
        sa.Column("start_hhmm", sa.String(), nullable=False, server_default="01:00"),
        sa.Column("end_hhmm", sa.String(), nullable=False, server_default="05:00"),
        sa.Column("action_scope", sa.JSON(), nullable=False, server_default=sa.text("'[]'::json")),
        sa.Column("label_selector", sa.JSON(), nullable=False, server_default=sa.text("'{}'::json")),
        sa.Column("saved_view_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("enforcement_mode", sa.String(), nullable=False, server_default="block"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["saved_view_id"], ["app_saved_views.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_app_maintenance_windows_name", "app_maintenance_windows", ["name"], unique=False)
    op.create_index("ix_app_maintenance_windows_enabled", "app_maintenance_windows", ["enabled"], unique=False)
    op.create_index("ix_app_maintenance_windows_saved_view_id", "app_maintenance_windows", ["saved_view_id"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_app_maintenance_windows_saved_view_id", table_name="app_maintenance_windows")
    op.drop_index("ix_app_maintenance_windows_enabled", table_name="app_maintenance_windows")
    op.drop_index("ix_app_maintenance_windows_name", table_name="app_maintenance_windows")
    op.drop_table("app_maintenance_windows")
