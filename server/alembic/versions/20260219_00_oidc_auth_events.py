"""add oidc_auth_events table

Revision ID: 20260219_00
Revises: 20260217_00
Create Date: 2026-02-19
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision = "20260219_00"
down_revision = "20260217_00"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "oidc_auth_events",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("provider", sa.String(), nullable=True),
        sa.Column("stage", sa.String(), nullable=False),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("error_code", sa.String(), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("correlation_id", sa.String(), nullable=False),
        sa.Column("username", sa.String(), nullable=True),
        sa.Column("email", sa.String(), nullable=True),
        sa.Column("subject", sa.String(), nullable=True),
        sa.Column("meta", sa.JSON(), nullable=False, server_default=sa.text("'{}'::json")),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_oidc_auth_events_provider", "oidc_auth_events", ["provider"], unique=False)
    op.create_index("ix_oidc_auth_events_stage", "oidc_auth_events", ["stage"], unique=False)
    op.create_index("ix_oidc_auth_events_status", "oidc_auth_events", ["status"], unique=False)
    op.create_index("ix_oidc_auth_events_error_code", "oidc_auth_events", ["error_code"], unique=False)
    op.create_index("ix_oidc_auth_events_correlation_id", "oidc_auth_events", ["correlation_id"], unique=False)
    op.create_index("ix_oidc_auth_events_username", "oidc_auth_events", ["username"], unique=False)
    op.create_index("ix_oidc_auth_events_email", "oidc_auth_events", ["email"], unique=False)
    op.create_index("ix_oidc_auth_events_subject", "oidc_auth_events", ["subject"], unique=False)
    op.create_index("ix_oidc_auth_events_created_at", "oidc_auth_events", ["created_at"], unique=False)
    op.create_index("ix_oidc_auth_events_stage_created", "oidc_auth_events", ["stage", "created_at"], unique=False)
    op.create_index("ix_oidc_auth_events_status_created", "oidc_auth_events", ["status", "created_at"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_oidc_auth_events_status_created", table_name="oidc_auth_events")
    op.drop_index("ix_oidc_auth_events_stage_created", table_name="oidc_auth_events")
    op.drop_index("ix_oidc_auth_events_created_at", table_name="oidc_auth_events")
    op.drop_index("ix_oidc_auth_events_subject", table_name="oidc_auth_events")
    op.drop_index("ix_oidc_auth_events_email", table_name="oidc_auth_events")
    op.drop_index("ix_oidc_auth_events_username", table_name="oidc_auth_events")
    op.drop_index("ix_oidc_auth_events_correlation_id", table_name="oidc_auth_events")
    op.drop_index("ix_oidc_auth_events_error_code", table_name="oidc_auth_events")
    op.drop_index("ix_oidc_auth_events_status", table_name="oidc_auth_events")
    op.drop_index("ix_oidc_auth_events_stage", table_name="oidc_auth_events")
    op.drop_index("ix_oidc_auth_events_provider", table_name="oidc_auth_events")
    op.drop_table("oidc_auth_events")
