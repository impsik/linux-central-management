"""Schema updates: app_users.role, ansible_runs, job indexes

This migration is written to be safe to run on databases that were previously
created via SQLAlchemy create_all() without Alembic.

Revision ID: 20260203_01
Revises: 
Create Date: 2026-02-03

"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "20260203_01"
down_revision = "20260203_00"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    dialect = bind.dialect.name

    # --- app_users.role ---
    if dialect == "postgresql":
        op.execute("ALTER TABLE app_users ADD COLUMN IF NOT EXISTS role VARCHAR NOT NULL DEFAULT 'operator'")
        op.execute("CREATE INDEX IF NOT EXISTS ix_app_users_role ON app_users (role)")
    else:
        # Best-effort for sqlite (tests/dev)
        # SQLite lacks IF NOT EXISTS for ADD COLUMN before 3.35; try plain add.
        try:
            op.add_column("app_users", sa.Column("role", sa.String(), nullable=False, server_default="operator"))
        except Exception:
            pass

    # --- host_users.home (legacy column) ---
    if dialect == "postgresql":
        op.execute("ALTER TABLE host_users ADD COLUMN IF NOT EXISTS home VARCHAR")
    else:
        try:
            op.add_column("host_users", sa.Column("home", sa.String(), nullable=True))
        except Exception:
            pass

    # --- ansible_runs table ---
    if dialect == "postgresql":
        op.execute(
            """
            CREATE TABLE IF NOT EXISTS ansible_runs (
              id uuid PRIMARY KEY,
              run_key varchar NOT NULL UNIQUE,
              playbook varchar NOT NULL,
              created_by varchar,
              targets json NOT NULL DEFAULT '[]'::json,
              extra_vars json NOT NULL DEFAULT '{}'::json,
              status varchar NOT NULL,
              rc integer,
              stdout text,
              stderr text,
              log_name varchar,
              log_path varchar,
              created_at timestamptz NOT NULL DEFAULT now(),
              finished_at timestamptz
            )
            """
        )
        op.execute("CREATE INDEX IF NOT EXISTS ix_ansible_runs_run_key ON ansible_runs (run_key)")
        op.execute("CREATE INDEX IF NOT EXISTS ix_ansible_runs_playbook ON ansible_runs (playbook)")
        op.execute("CREATE INDEX IF NOT EXISTS ix_ansible_runs_created_by ON ansible_runs (created_by)")
        op.execute("CREATE INDEX IF NOT EXISTS ix_ansible_runs_status ON ansible_runs (status)")
        op.execute("CREATE INDEX IF NOT EXISTS ix_ansible_runs_created_at ON ansible_runs (created_at)")
    else:
        # SQLite best-effort: create if missing
        try:
            op.create_table(
                "ansible_runs",
                sa.Column("id", sa.String(), primary_key=True),
                sa.Column("run_key", sa.String(), nullable=False, unique=True),
                sa.Column("playbook", sa.String(), nullable=False),
                sa.Column("created_by", sa.String()),
                sa.Column("targets", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
                sa.Column("extra_vars", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
                sa.Column("status", sa.String(), nullable=False),
                sa.Column("rc", sa.Integer()),
                sa.Column("stdout", sa.Text()),
                sa.Column("stderr", sa.Text()),
                sa.Column("log_name", sa.String()),
                sa.Column("log_path", sa.String()),
                sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
                sa.Column("finished_at", sa.DateTime(timezone=True)),
            )
        except Exception:
            pass

    # --- jobs indexes (Postgres safe) ---
    if dialect == "postgresql":
        op.execute("CREATE INDEX IF NOT EXISTS ix_jobs_job_key ON jobs (job_key)")
        op.execute("CREATE INDEX IF NOT EXISTS ix_jobs_created_by ON jobs (created_by)")
        op.execute("CREATE INDEX IF NOT EXISTS ix_jobs_job_type ON jobs (job_type)")
        op.execute("CREATE INDEX IF NOT EXISTS ix_jobs_created_at ON jobs (created_at)")

        op.execute("CREATE INDEX IF NOT EXISTS ix_job_runs_job_id ON job_runs (job_id)")
        op.execute("CREATE INDEX IF NOT EXISTS ix_job_runs_agent_id ON job_runs (agent_id)")
        op.execute("CREATE INDEX IF NOT EXISTS ix_job_runs_status ON job_runs (status)")


def downgrade() -> None:
    # Non-destructive downgrade: keep data.
    pass
