"""missing runtime tables catch-up

Revision ID: 20260419_01
Revises: 20260419_00
Create Date: 2026-04-19
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "20260419_01"
down_revision = "20260419_00"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "host_cve_status",
        sa.Column("host_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("cve", sa.String(), nullable=False),
        sa.Column("package_name", sa.String(), nullable=True),
        sa.Column("fixed_version", sa.String(), nullable=True),
        sa.Column("status", sa.String(), nullable=False, server_default="open"),
        sa.Column("severity", sa.String(), nullable=True),
        sa.Column("source", sa.String(), nullable=True),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["host_id"], ["hosts.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("host_id", "cve"),
    )
    op.create_index("ix_host_cve_status_status", "host_cve_status", ["status"])
    op.create_index("ix_host_cve_status_severity", "host_cve_status", ["severity"])

    op.create_table(
        "app_saved_views",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("scope", sa.String(), nullable=False),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("is_shared", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("is_default_startup", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["user_id"], ["app_users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("user_id", "scope", "name", name="uq_app_saved_views_user_scope_name"),
    )
    op.create_index("ix_app_saved_views_user_id", "app_saved_views", ["user_id"])
    op.create_index("ix_app_saved_views_scope", "app_saved_views", ["scope"])
    op.create_index("ix_app_saved_views_is_shared", "app_saved_views", ["is_shared"])
    op.create_index("ix_app_saved_views_is_default_startup", "app_saved_views", ["is_default_startup"])
    op.create_index("ix_app_saved_views_user_scope", "app_saved_views", ["user_id", "scope"])

    op.create_table(
        "user_ssh_keys",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("name", sa.String(), nullable=False, server_default=""),
        sa.Column("public_key", sa.Text(), nullable=False),
        sa.Column("fingerprint", sa.String(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["app_users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_user_ssh_keys_user_id", "user_ssh_keys", ["user_id"])
    op.create_index("ix_user_ssh_keys_fingerprint", "user_ssh_keys", ["fingerprint"])
    op.create_index("ix_user_ssh_keys_created_at", "user_ssh_keys", ["created_at"])
    op.create_index("ix_user_ssh_keys_user_created", "user_ssh_keys", ["user_id", "created_at"])

    op.create_table(
        "high_risk_action_requests",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("action", sa.String(), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("status", sa.String(), nullable=False, server_default="pending"),
        sa.Column("approved_by", sa.String(), nullable=True),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("execution_ref", sa.String(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["app_users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_high_risk_action_requests_user_id", "high_risk_action_requests", ["user_id"])
    op.create_index("ix_high_risk_action_requests_action", "high_risk_action_requests", ["action"])
    op.create_index("ix_high_risk_action_requests_status", "high_risk_action_requests", ["status"])
    op.create_index("ix_high_risk_action_requests_approved_by", "high_risk_action_requests", ["approved_by"])
    op.create_index("ix_high_risk_action_requests_execution_ref", "high_risk_action_requests", ["execution_ref"])
    op.create_index("ix_high_risk_action_requests_created_at", "high_risk_action_requests", ["created_at"])

    op.create_table(
        "ssh_key_deployment_requests",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("key_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("agent_ids", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("sudo_profile", sa.String(), nullable=False, server_default="B"),
        sa.Column("status", sa.String(), nullable=False, server_default="pending"),
        sa.Column("approved_by", sa.String(), nullable=True),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["app_users.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["key_id"], ["user_ssh_keys.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_ssh_key_deployment_requests_user_id", "ssh_key_deployment_requests", ["user_id"])
    op.create_index("ix_ssh_key_deployment_requests_key_id", "ssh_key_deployment_requests", ["key_id"])
    op.create_index("ix_ssh_key_deployment_requests_status", "ssh_key_deployment_requests", ["status"])
    op.create_index("ix_ssh_key_deploy_req_status", "ssh_key_deployment_requests", ["status"])
    op.create_index("ix_ssh_key_deployment_requests_approved_by", "ssh_key_deployment_requests", ["approved_by"])
    op.create_index("ix_ssh_key_deployment_requests_created_at", "ssh_key_deployment_requests", ["created_at"])

    op.create_table(
        "notification_dedupe_state",
        sa.Column("dedupe_key", sa.String(), nullable=False),
        sa.Column("kind", sa.String(), nullable=False),
        sa.Column("severity", sa.String(), nullable=False),
        sa.Column("last_emitted_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_title", sa.String(), nullable=True),
        sa.PrimaryKeyConstraint("dedupe_key"),
    )
    op.create_index("ix_notification_dedupe_state_kind", "notification_dedupe_state", ["kind"])
    op.create_index("ix_notification_dedupe_state_severity", "notification_dedupe_state", ["severity"])
    op.create_index("ix_notification_dedupe_state_last_emitted_at", "notification_dedupe_state", ["last_emitted_at"])


def downgrade() -> None:
    op.drop_index("ix_notification_dedupe_state_last_emitted_at", table_name="notification_dedupe_state")
    op.drop_index("ix_notification_dedupe_state_severity", table_name="notification_dedupe_state")
    op.drop_index("ix_notification_dedupe_state_kind", table_name="notification_dedupe_state")
    op.drop_table("notification_dedupe_state")

    op.drop_index("ix_ssh_key_deployment_requests_created_at", table_name="ssh_key_deployment_requests")
    op.drop_index("ix_ssh_key_deployment_requests_approved_by", table_name="ssh_key_deployment_requests")
    op.drop_index("ix_ssh_key_deploy_req_status", table_name="ssh_key_deployment_requests")
    op.drop_index("ix_ssh_key_deployment_requests_status", table_name="ssh_key_deployment_requests")
    op.drop_index("ix_ssh_key_deployment_requests_key_id", table_name="ssh_key_deployment_requests")
    op.drop_index("ix_ssh_key_deployment_requests_user_id", table_name="ssh_key_deployment_requests")
    op.drop_table("ssh_key_deployment_requests")

    op.drop_index("ix_high_risk_action_requests_created_at", table_name="high_risk_action_requests")
    op.drop_index("ix_high_risk_action_requests_execution_ref", table_name="high_risk_action_requests")
    op.drop_index("ix_high_risk_action_requests_approved_by", table_name="high_risk_action_requests")
    op.drop_index("ix_high_risk_action_requests_status", table_name="high_risk_action_requests")
    op.drop_index("ix_high_risk_action_requests_action", table_name="high_risk_action_requests")
    op.drop_index("ix_high_risk_action_requests_user_id", table_name="high_risk_action_requests")
    op.drop_table("high_risk_action_requests")

    op.drop_index("ix_user_ssh_keys_user_created", table_name="user_ssh_keys")
    op.drop_index("ix_user_ssh_keys_created_at", table_name="user_ssh_keys")
    op.drop_index("ix_user_ssh_keys_fingerprint", table_name="user_ssh_keys")
    op.drop_index("ix_user_ssh_keys_user_id", table_name="user_ssh_keys")
    op.drop_table("user_ssh_keys")

    op.drop_index("ix_app_saved_views_user_scope", table_name="app_saved_views")
    op.drop_index("ix_app_saved_views_is_default_startup", table_name="app_saved_views")
    op.drop_index("ix_app_saved_views_is_shared", table_name="app_saved_views")
    op.drop_index("ix_app_saved_views_scope", table_name="app_saved_views")
    op.drop_index("ix_app_saved_views_user_id", table_name="app_saved_views")
    op.drop_table("app_saved_views")

    op.drop_index("ix_host_cve_status_severity", table_name="host_cve_status")
    op.drop_index("ix_host_cve_status_status", table_name="host_cve_status")
    op.drop_table("host_cve_status")
