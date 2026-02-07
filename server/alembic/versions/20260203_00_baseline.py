"""Baseline schema (create tables)

Creates core tables for a fresh install.
Written to be safe-ish on Postgres by using CREATE TABLE IF NOT EXISTS.

Revision ID: 20260203_00
Revises:
Create Date: 2026-02-03

"""

from __future__ import annotations

from alembic import op

revision = "20260203_00"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    dialect = bind.dialect.name

    if dialect != "postgresql":
        # For sqlite/dev we rely on create_all(), or future sqlite-specific migrations.
        return

    # NOTE: This uses raw SQL to support IF NOT EXISTS.
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS hosts (
          id uuid PRIMARY KEY,
          agent_id varchar NOT NULL UNIQUE,
          hostname varchar NOT NULL,
          fqdn varchar,
          ip_address varchar,
          os_id varchar,
          os_version varchar,
          kernel varchar,
          labels json NOT NULL DEFAULT '{}'::json,
          last_seen timestamptz,
          created_at timestamptz NOT NULL DEFAULT now(),
          updated_at timestamptz NOT NULL DEFAULT now()
        );

        CREATE TABLE IF NOT EXISTS host_packages (
          host_id uuid NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
          name varchar NOT NULL,
          arch varchar NOT NULL,
          version varchar NOT NULL,
          manager varchar NOT NULL,
          collected_at timestamptz NOT NULL,
          PRIMARY KEY (host_id, name, arch)
        );

        CREATE TABLE IF NOT EXISTS host_package_updates (
          host_id uuid NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
          name varchar NOT NULL,
          installed_version varchar,
          candidate_version varchar,
          update_available boolean NOT NULL DEFAULT false,
          checked_at timestamptz NOT NULL DEFAULT now(),
          PRIMARY KEY (host_id, name)
        );

        CREATE TABLE IF NOT EXISTS host_users (
          host_id uuid NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
          username varchar NOT NULL,
          uid integer,
          gid integer,
          home varchar,
          shell varchar,
          has_sudo boolean NOT NULL DEFAULT false,
          is_locked boolean NOT NULL DEFAULT false,
          first_seen timestamptz NOT NULL DEFAULT now(),
          last_seen timestamptz NOT NULL DEFAULT now(),
          PRIMARY KEY (host_id, username)
        );

        CREATE TABLE IF NOT EXISTS jobs (
          id uuid PRIMARY KEY,
          job_key varchar NOT NULL UNIQUE,
          created_by varchar,
          job_type varchar NOT NULL,
          payload json NOT NULL,
          selector json NOT NULL,
          created_at timestamptz NOT NULL DEFAULT now()
        );

        CREATE TABLE IF NOT EXISTS job_runs (
          id uuid PRIMARY KEY,
          job_id uuid NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
          agent_id varchar NOT NULL,
          status varchar NOT NULL,
          started_at timestamptz,
          finished_at timestamptz,
          exit_code integer,
          stdout text,
          stderr text,
          error text,
          CONSTRAINT uq_job_agent UNIQUE (job_id, agent_id)
        );

        CREATE TABLE IF NOT EXISTS host_load_metrics (
          id uuid PRIMARY KEY,
          agent_id varchar NOT NULL,
          load_1min varchar NOT NULL,
          load_5min varchar NOT NULL,
          load_15min varchar NOT NULL,
          recorded_at timestamptz NOT NULL DEFAULT now()
        );

        CREATE TABLE IF NOT EXISTS app_users (
          id uuid PRIMARY KEY,
          username varchar NOT NULL UNIQUE,
          password_hash varchar NOT NULL,
          role varchar NOT NULL DEFAULT 'operator',
          is_active boolean NOT NULL DEFAULT true,
          created_at timestamptz NOT NULL DEFAULT now()
        );

        CREATE TABLE IF NOT EXISTS app_sessions (
          id uuid PRIMARY KEY,
          user_id uuid NOT NULL REFERENCES app_users(id) ON DELETE CASCADE,
          token_sha256 varchar NOT NULL UNIQUE,
          created_at timestamptz NOT NULL DEFAULT now(),
          expires_at timestamptz NOT NULL
        );
        """
    )

    # Baseline indexes
    op.execute("CREATE INDEX IF NOT EXISTS ix_hosts_agent_id ON hosts (agent_id)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_host_package_updates_host_id ON host_package_updates (host_id)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_host_package_updates_name ON host_package_updates (name)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_host_users_host_id ON host_users (host_id)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_host_users_username ON host_users (username)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_job_runs_job_id ON job_runs (job_id)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_job_runs_agent_id ON job_runs (agent_id)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_job_runs_status ON job_runs (status)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_jobs_created_at ON jobs (created_at)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_jobs_job_type ON jobs (job_type)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_jobs_created_by ON jobs (created_by)")


def downgrade() -> None:
    # Non-destructive: keep data.
    pass
