"""cron jobs tables

Revision ID: 20260414_00
Revises: 20260225_02
Create Date: 2026-04-14
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "20260414_00"
down_revision = "20260225_02"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "cron_jobs",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("name", sa.String(), nullable=False, server_default=""),
        sa.Column("run_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("action", sa.String(), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("selector", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("status", sa.String(), nullable=False, server_default="scheduled"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["app_users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_cron_jobs_user_id", "cron_jobs", ["user_id"])
    op.create_index("ix_cron_jobs_run_at", "cron_jobs", ["run_at"])
    op.create_index("ix_cron_jobs_action", "cron_jobs", ["action"])
    op.create_index("ix_cron_jobs_status", "cron_jobs", ["status"])
    op.create_index("ix_cron_jobs_created_at", "cron_jobs", ["created_at"])

    op.create_table(
        "cron_job_runs",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("cron_job_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("job_key", sa.String(), nullable=True),
        sa.Column("status", sa.String(), nullable=False, server_default="queued"),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["cron_job_id"], ["cron_jobs.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_cron_job_runs_cron_job_id", "cron_job_runs", ["cron_job_id"])
    op.create_index("ix_cron_job_runs_job_key", "cron_job_runs", ["job_key"])
    op.create_index("ix_cron_job_runs_status", "cron_job_runs", ["status"])
    op.create_index("ix_cron_job_runs_created_at", "cron_job_runs", ["created_at"])


def downgrade() -> None:
    op.drop_index("ix_cron_job_runs_created_at", table_name="cron_job_runs")
    op.drop_index("ix_cron_job_runs_status", table_name="cron_job_runs")
    op.drop_index("ix_cron_job_runs_job_key", table_name="cron_job_runs")
    op.drop_index("ix_cron_job_runs_cron_job_id", table_name="cron_job_runs")
    op.drop_table("cron_job_runs")

    op.drop_index("ix_cron_jobs_created_at", table_name="cron_jobs")
    op.drop_index("ix_cron_jobs_status", table_name="cron_jobs")
    op.drop_index("ix_cron_jobs_action", table_name="cron_jobs")
    op.drop_index("ix_cron_jobs_run_at", table_name="cron_jobs")
    op.drop_index("ix_cron_jobs_user_id", table_name="cron_jobs")
    op.drop_table("cron_jobs")
