"""add backup verification policy table

Revision ID: 20260225_01
Revises: 20260225_00
Create Date: 2026-02-25
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "20260225_01"
down_revision = "20260225_00"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "backup_verification_policy",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("backup_path", sa.String(), nullable=False),
        sa.Column("expected_sha256", sa.String(), nullable=True),
        sa.Column("expected_schema_version", sa.Integer(), nullable=True),
        sa.Column("schedule_kind", sa.String(), nullable=False, server_default="daily"),
        sa.Column("timezone", sa.String(), nullable=False, server_default="UTC"),
        sa.Column("time_hhmm", sa.String(), nullable=False, server_default="03:00"),
        sa.Column("weekday", sa.Integer(), nullable=True),
        sa.Column("stale_after_hours", sa.Integer(), nullable=False, server_default="36"),
        sa.Column("alert_on_failure", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("alert_on_stale", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("next_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_status", sa.String(), nullable=True),
        sa.Column("last_error", sa.String(), nullable=True),
        sa.Column("last_alert_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_backup_verification_policy_next_run_at", "backup_verification_policy", ["next_run_at"], unique=False)
    op.create_index("ix_backup_verification_policy_last_run_at", "backup_verification_policy", ["last_run_at"], unique=False)
    op.create_index("ix_backup_verification_policy_last_alert_at", "backup_verification_policy", ["last_alert_at"], unique=False)
    op.create_index("ix_backup_verification_policy_created_at", "backup_verification_policy", ["created_at"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_backup_verification_policy_created_at", table_name="backup_verification_policy")
    op.drop_index("ix_backup_verification_policy_last_alert_at", table_name="backup_verification_policy")
    op.drop_index("ix_backup_verification_policy_last_run_at", table_name="backup_verification_policy")
    op.drop_index("ix_backup_verification_policy_next_run_at", table_name="backup_verification_policy")
    op.drop_table("backup_verification_policy")
