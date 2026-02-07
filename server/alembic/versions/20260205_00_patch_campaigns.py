"""Patch campaigns + audit log

Revision ID: 20260205_00
Revises: 20260203_01
Create Date: 2026-02-05

"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "20260205_00"
down_revision = "20260203_01"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    dialect = bind.dialect.name

    if dialect == "postgresql":
        op.execute(
            """
            CREATE TABLE IF NOT EXISTS patch_campaigns (
              id uuid PRIMARY KEY,
              campaign_key varchar NOT NULL UNIQUE,
              created_by varchar,
              kind varchar NOT NULL,
              selector json NOT NULL DEFAULT '{}'::json,
              rings json NOT NULL DEFAULT '[]'::json,
              window_start timestamptz NOT NULL,
              window_end timestamptz NOT NULL,
              concurrency integer NOT NULL DEFAULT 5,
              reboot_if_needed boolean NOT NULL DEFAULT false,
              status varchar NOT NULL DEFAULT 'scheduled',
              created_at timestamptz NOT NULL DEFAULT now(),
              started_at timestamptz,
              finished_at timestamptz
            )
            """
        )
        op.execute("CREATE INDEX IF NOT EXISTS ix_patch_campaigns_campaign_key ON patch_campaigns (campaign_key)")
        op.execute("CREATE INDEX IF NOT EXISTS ix_patch_campaigns_kind ON patch_campaigns (kind)")
        op.execute("CREATE INDEX IF NOT EXISTS ix_patch_campaigns_created_by ON patch_campaigns (created_by)")
        op.execute("CREATE INDEX IF NOT EXISTS ix_patch_campaigns_window_start ON patch_campaigns (window_start)")
        op.execute("CREATE INDEX IF NOT EXISTS ix_patch_campaigns_window_end ON patch_campaigns (window_end)")
        op.execute("CREATE INDEX IF NOT EXISTS ix_patch_campaigns_status ON patch_campaigns (status)")
        op.execute("CREATE INDEX IF NOT EXISTS ix_patch_campaigns_created_at ON patch_campaigns (created_at)")

        op.execute(
            """
            CREATE TABLE IF NOT EXISTS patch_campaign_hosts (
              id uuid PRIMARY KEY,
              campaign_id uuid NOT NULL REFERENCES patch_campaigns(id) ON DELETE CASCADE,
              agent_id varchar NOT NULL,
              ring integer NOT NULL DEFAULT 0,
              status varchar NOT NULL DEFAULT 'queued',
              job_key_upgrade varchar,
              job_key_reboot_check varchar,
              job_key_reboot varchar,
              reboot_required boolean,
              error text,
              started_at timestamptz,
              finished_at timestamptz,
              CONSTRAINT uq_campaign_agent UNIQUE (campaign_id, agent_id)
            )
            """
        )
        op.execute("CREATE INDEX IF NOT EXISTS ix_patch_campaign_hosts_campaign_id ON patch_campaign_hosts (campaign_id)")
        op.execute("CREATE INDEX IF NOT EXISTS ix_patch_campaign_hosts_agent_id ON patch_campaign_hosts (agent_id)")
        op.execute("CREATE INDEX IF NOT EXISTS ix_patch_campaign_hosts_ring ON patch_campaign_hosts (ring)")
        op.execute("CREATE INDEX IF NOT EXISTS ix_patch_campaign_hosts_status ON patch_campaign_hosts (status)")
        op.execute(
            "CREATE INDEX IF NOT EXISTS ix_patch_campaign_hosts_campaign_ring ON patch_campaign_hosts (campaign_id, ring)"
        )

        op.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_log (
              id uuid PRIMARY KEY,
              actor varchar,
              action varchar NOT NULL,
              entity_type varchar NOT NULL,
              entity_key varchar,
              detail json NOT NULL DEFAULT '{}'::json,
              created_at timestamptz NOT NULL DEFAULT now()
            )
            """
        )
        op.execute("CREATE INDEX IF NOT EXISTS ix_audit_log_actor ON audit_log (actor)")
        op.execute("CREATE INDEX IF NOT EXISTS ix_audit_log_action ON audit_log (action)")
        op.execute("CREATE INDEX IF NOT EXISTS ix_audit_log_entity_type ON audit_log (entity_type)")
        op.execute("CREATE INDEX IF NOT EXISTS ix_audit_log_entity_key ON audit_log (entity_key)")
        op.execute("CREATE INDEX IF NOT EXISTS ix_audit_log_created_at ON audit_log (created_at)")

    else:
        # SQLite / dev best-effort
        try:
            op.create_table(
                "patch_campaigns",
                sa.Column("id", sa.String(), primary_key=True),
                sa.Column("campaign_key", sa.String(), nullable=False, unique=True),
                sa.Column("created_by", sa.String()),
                sa.Column("kind", sa.String(), nullable=False),
                sa.Column("selector", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
                sa.Column("rings", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
                sa.Column("window_start", sa.DateTime(timezone=True), nullable=False),
                sa.Column("window_end", sa.DateTime(timezone=True), nullable=False),
                sa.Column("concurrency", sa.Integer(), nullable=False, server_default="5"),
                sa.Column("reboot_if_needed", sa.Boolean(), nullable=False, server_default=sa.text("0")),
                sa.Column("status", sa.String(), nullable=False, server_default="scheduled"),
                sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
                sa.Column("started_at", sa.DateTime(timezone=True)),
                sa.Column("finished_at", sa.DateTime(timezone=True)),
            )
        except Exception:
            pass

        try:
            op.create_table(
                "patch_campaign_hosts",
                sa.Column("id", sa.String(), primary_key=True),
                sa.Column("campaign_id", sa.String(), nullable=False),
                sa.Column("agent_id", sa.String(), nullable=False),
                sa.Column("ring", sa.Integer(), nullable=False, server_default="0"),
                sa.Column("status", sa.String(), nullable=False, server_default="queued"),
                sa.Column("job_key_upgrade", sa.String()),
                sa.Column("job_key_reboot_check", sa.String()),
                sa.Column("job_key_reboot", sa.String()),
                sa.Column("reboot_required", sa.Boolean()),
                sa.Column("error", sa.Text()),
                sa.Column("started_at", sa.DateTime(timezone=True)),
                sa.Column("finished_at", sa.DateTime(timezone=True)),
                sa.UniqueConstraint("campaign_id", "agent_id", name="uq_campaign_agent"),
            )
        except Exception:
            pass

        try:
            op.create_table(
                "audit_log",
                sa.Column("id", sa.String(), primary_key=True),
                sa.Column("actor", sa.String()),
                sa.Column("action", sa.String(), nullable=False),
                sa.Column("entity_type", sa.String(), nullable=False),
                sa.Column("entity_key", sa.String()),
                sa.Column("detail", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
                sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
            )
        except Exception:
            pass


def downgrade() -> None:
    # Non-destructive downgrade.
    pass
