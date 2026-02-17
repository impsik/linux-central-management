"""add app_user_scopes table

Revision ID: 20260217_00
Revises: 20260213_01
Create Date: 2026-02-17
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = "20260217_00"
down_revision = "20260213_01"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "app_user_scopes",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("scope_type", sa.String(), nullable=False, server_default="label_selector"),
        sa.Column("selector", sa.JSON(), nullable=False, server_default=sa.text("'{}'::json")),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["app_users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_app_user_scopes_user_id", "app_user_scopes", ["user_id"], unique=False)
    op.create_index("ix_app_user_scopes_scope_type", "app_user_scopes", ["scope_type"], unique=False)
    op.create_index("ix_app_user_scopes_user_scope_type", "app_user_scopes", ["user_id", "scope_type"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_app_user_scopes_user_scope_type", table_name="app_user_scopes")
    op.drop_index("ix_app_user_scopes_scope_type", table_name="app_user_scopes")
    op.drop_index("ix_app_user_scopes_user_id", table_name="app_user_scopes")
    op.drop_table("app_user_scopes")
