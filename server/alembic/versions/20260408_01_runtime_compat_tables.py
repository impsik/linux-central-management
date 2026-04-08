"""add runtime compatibility tables missing from older Alembic chain

Revision ID: 20260408_01
Revises: 20260408_00
Create Date: 2026-04-08
"""

from alembic import op


revision = "20260408_01"
down_revision = "20260408_00"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    dialect = bind.dialect.name

    if dialect != "postgresql":
        return

    op.execute(
        """
        CREATE TABLE IF NOT EXISTS host_metrics_snapshots (
          id uuid PRIMARY KEY,
          agent_id varchar NOT NULL,
          disk_percent_used varchar,
          mem_percent_used varchar,
          load_1min varchar,
          vcpus integer,
          recorded_at timestamptz NOT NULL DEFAULT now()
        )
        """
    )
    op.execute("CREATE INDEX IF NOT EXISTS ix_host_metrics_snapshots_agent_id ON host_metrics_snapshots (agent_id)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_host_metrics_snapshots_recorded_at ON host_metrics_snapshots (recorded_at)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_host_metrics_snapshots_agent_recorded ON host_metrics_snapshots (agent_id, recorded_at)")

    op.execute(
        """
        CREATE TABLE IF NOT EXISTS cron_jobs (
          id uuid PRIMARY KEY,
          user_id uuid NOT NULL REFERENCES app_users(id) ON DELETE CASCADE,
          name varchar NOT NULL DEFAULT '',
          run_at timestamptz NOT NULL,
          action varchar NOT NULL,
          payload json NOT NULL DEFAULT '{}'::json,
          selector json NOT NULL DEFAULT '{}'::json,
          status varchar NOT NULL DEFAULT 'scheduled',
          created_at timestamptz NOT NULL DEFAULT now(),
          started_at timestamptz,
          finished_at timestamptz,
          last_error text
        )
        """
    )
    op.execute("CREATE INDEX IF NOT EXISTS ix_cron_jobs_user_id ON cron_jobs (user_id)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_cron_jobs_run_at ON cron_jobs (run_at)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_cron_jobs_action ON cron_jobs (action)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_cron_jobs_status ON cron_jobs (status)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_cron_jobs_created_at ON cron_jobs (created_at)")

    op.execute(
        """
        CREATE TABLE IF NOT EXISTS cron_job_runs (
          id uuid PRIMARY KEY,
          cron_job_id uuid NOT NULL REFERENCES cron_jobs(id) ON DELETE CASCADE,
          job_key varchar,
          status varchar NOT NULL DEFAULT 'queued',
          started_at timestamptz,
          finished_at timestamptz,
          error text,
          created_at timestamptz NOT NULL DEFAULT now()
        )
        """
    )
    op.execute("CREATE INDEX IF NOT EXISTS ix_cron_job_runs_cron_job_id ON cron_job_runs (cron_job_id)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_cron_job_runs_job_key ON cron_job_runs (job_key)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_cron_job_runs_status ON cron_job_runs (status)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_cron_job_runs_created_at ON cron_job_runs (created_at)")

    op.execute(
        """
        CREATE TABLE IF NOT EXISTS user_ssh_keys (
          id uuid PRIMARY KEY,
          user_id uuid NOT NULL REFERENCES app_users(id) ON DELETE CASCADE,
          name varchar NOT NULL DEFAULT '',
          public_key text NOT NULL,
          fingerprint varchar NOT NULL,
          created_at timestamptz NOT NULL DEFAULT now(),
          revoked_at timestamptz
        )
        """
    )
    op.execute("CREATE INDEX IF NOT EXISTS ix_user_ssh_keys_user_id ON user_ssh_keys (user_id)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_user_ssh_keys_fingerprint ON user_ssh_keys (fingerprint)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_user_ssh_keys_created_at ON user_ssh_keys (created_at)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_user_ssh_keys_user_created ON user_ssh_keys (user_id, created_at)")

    op.execute(
        """
        CREATE TABLE IF NOT EXISTS high_risk_action_requests (
          id uuid PRIMARY KEY,
          user_id uuid NOT NULL REFERENCES app_users(id) ON DELETE CASCADE,
          action varchar NOT NULL,
          payload json NOT NULL DEFAULT '{}'::json,
          status varchar NOT NULL DEFAULT 'pending',
          approved_by varchar,
          approved_at timestamptz,
          error text,
          execution_ref varchar,
          created_at timestamptz NOT NULL DEFAULT now(),
          finished_at timestamptz
        )
        """
    )
    op.execute("CREATE INDEX IF NOT EXISTS ix_high_risk_action_requests_user_id ON high_risk_action_requests (user_id)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_high_risk_action_requests_action ON high_risk_action_requests (action)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_high_risk_action_requests_status ON high_risk_action_requests (status)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_high_risk_action_requests_approved_by ON high_risk_action_requests (approved_by)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_high_risk_action_requests_execution_ref ON high_risk_action_requests (execution_ref)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_high_risk_action_requests_created_at ON high_risk_action_requests (created_at)")

    op.execute(
        """
        CREATE TABLE IF NOT EXISTS ssh_key_deployment_requests (
          id uuid PRIMARY KEY,
          user_id uuid NOT NULL REFERENCES app_users(id) ON DELETE CASCADE,
          key_id uuid NOT NULL REFERENCES user_ssh_keys(id) ON DELETE CASCADE,
          agent_ids json NOT NULL DEFAULT '[]'::json,
          sudo_profile varchar NOT NULL DEFAULT 'B',
          status varchar NOT NULL DEFAULT 'pending',
          approved_by varchar,
          approved_at timestamptz,
          error text,
          created_at timestamptz NOT NULL DEFAULT now(),
          finished_at timestamptz
        )
        """
    )
    op.execute("CREATE INDEX IF NOT EXISTS ix_ssh_key_deployment_requests_user_id ON ssh_key_deployment_requests (user_id)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_ssh_key_deployment_requests_key_id ON ssh_key_deployment_requests (key_id)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_ssh_key_deployment_requests_status ON ssh_key_deployment_requests (status)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_ssh_key_deployment_requests_approved_by ON ssh_key_deployment_requests (approved_by)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_ssh_key_deployment_requests_created_at ON ssh_key_deployment_requests (created_at)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_ssh_key_deploy_req_status ON ssh_key_deployment_requests (status)")

    op.execute(
        """
        CREATE TABLE IF NOT EXISTS notification_dedupe_state (
          dedupe_key varchar PRIMARY KEY,
          kind varchar NOT NULL,
          severity varchar NOT NULL,
          last_emitted_at timestamptz NOT NULL,
          last_title varchar
        )
        """
    )
    op.execute("CREATE INDEX IF NOT EXISTS ix_notification_dedupe_state_kind ON notification_dedupe_state (kind)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_notification_dedupe_state_severity ON notification_dedupe_state (severity)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_notification_dedupe_state_last_emitted_at ON notification_dedupe_state (last_emitted_at)")


def downgrade() -> None:
    # Compatibility migration: keep data on downgrade.
    pass
