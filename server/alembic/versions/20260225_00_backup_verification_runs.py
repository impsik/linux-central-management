"""add backup verification runs table

Revision ID: 20260225_00
Revises: 20260221_00
Create Date: 2026-02-25
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision = "20260225_00"
down_revision = "20260221_00"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "backup_verification_runs",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("backup_path", sa.String(), nullable=False),
        sa.Column("checksum_algorithm", sa.String(), nullable=False, server_default="sha256"),
        sa.Column("checksum_actual", sa.String(), nullable=False),
        sa.Column("checksum_expected", sa.String(), nullable=True),
        sa.Column("integrity_ok", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("restore_ok", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("compatibility_ok", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("schema_version", sa.Integer(), nullable=True),
        sa.Column("expected_schema_version", sa.Integer(), nullable=True),
        sa.Column("artifact_path", sa.String(), nullable=False),
        sa.Column("detail", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("created_by", sa.String(), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_backup_verification_runs_status", "backup_verification_runs", ["status"], unique=False)
    op.create_index("ix_backup_verification_runs_created_by", "backup_verification_runs", ["created_by"], unique=False)
    op.create_index("ix_backup_verification_runs_started_at", "backup_verification_runs", ["started_at"], unique=False)
    op.create_index("ix_backup_verification_runs_finished_at", "backup_verification_runs", ["finished_at"], unique=False)
    op.create_index("ix_backup_verification_runs_created_at", "backup_verification_runs", ["created_at"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_backup_verification_runs_created_at", table_name="backup_verification_runs")
    op.drop_index("ix_backup_verification_runs_finished_at", table_name="backup_verification_runs")
    op.drop_index("ix_backup_verification_runs_started_at", table_name="backup_verification_runs")
    op.drop_index("ix_backup_verification_runs_created_by", table_name="backup_verification_runs")
    op.drop_index("ix_backup_verification_runs_status", table_name="backup_verification_runs")
    op.drop_table("backup_verification_runs")
