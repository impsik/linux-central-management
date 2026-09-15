"""Index bounded cleanup of completed automatic metrics jobs."""

from alembic import op

revision = "20260914_01"
down_revision = "20260914_00"
branch_labels = None
depends_on = None


def upgrade():
    op.create_index("ix_job_runs_status_finished_id", "job_runs", ["status", "finished_at", "id"])


def downgrade():
    op.drop_index("ix_job_runs_status_finished_id", table_name="job_runs")
