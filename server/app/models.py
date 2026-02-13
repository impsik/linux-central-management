import uuid
from sqlalchemy import Column, String, DateTime, Integer, ForeignKey, JSON, Text, UniqueConstraint, Boolean, Index
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func
from .db import Base

class Host(Base):
    __tablename__ = "hosts"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    agent_id = Column(String, unique=True, nullable=False)
    hostname = Column(String, nullable=False)
    fqdn = Column(String)
    ip_address = Column(String)  # IP address of the agent (captured from registration requests)
    os_id = Column(String)
    os_version = Column(String)
    kernel = Column(String)
    labels = Column(JSON, nullable=False, default=dict)
    last_seen = Column(DateTime(timezone=True))
    reboot_required = Column(Boolean, nullable=False, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)

class HostPackage(Base):
    __tablename__ = "host_packages"
    host_id = Column(UUID(as_uuid=True), ForeignKey("hosts.id", ondelete="CASCADE"), primary_key=True)
    name = Column(String, primary_key=True)
    arch = Column(String, primary_key=True)
    version = Column(String, nullable=False)
    manager = Column(String, nullable=False)
    collected_at = Column(DateTime(timezone=True), nullable=False)

class HostPackageUpdate(Base):
    __tablename__ = "host_package_updates"
    host_id = Column(UUID(as_uuid=True), ForeignKey("hosts.id", ondelete="CASCADE"), primary_key=True)
    name = Column(String, primary_key=True)
    installed_version = Column(String)
    candidate_version = Column(String)
    is_security = Column(Boolean, nullable=False, default=False)
    update_available = Column(Boolean, nullable=False, default=False)
    checked_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False, index=True)

    __table_args__ = (
        Index("ix_host_package_updates_host_id", "host_id"),
        Index("ix_host_package_updates_name", "name"),
    )


class HostCVEStatus(Base):
    __tablename__ = "host_cve_status"

    host_id = Column(UUID(as_uuid=True), ForeignKey("hosts.id", ondelete="CASCADE"), primary_key=True)
    cve = Column(String, primary_key=True)

    affected = Column(Boolean, nullable=False, default=False, index=True)
    summary = Column(String)

    checked_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False, index=True)

    # raw output (best-effort, may be truncated by agent)
    raw = Column(Text)

    __table_args__ = (
        Index("ix_host_cve_status_host_id", "host_id"),
        Index("ix_host_cve_status_cve", "cve"),
        Index("ix_host_cve_status_cve_affected", "cve", "affected"),
    )

class HostUser(Base):
    __tablename__ = "host_users"
    host_id = Column(UUID(as_uuid=True), ForeignKey("hosts.id", ondelete="CASCADE"), primary_key=True)
    username = Column(String, primary_key=True)
    uid = Column(Integer)
    gid = Column(Integer)
    home = Column(String)
    shell = Column(String)
    has_sudo = Column(Boolean, nullable=False, default=False)
    is_locked = Column(Boolean, nullable=False, default=False)
    first_seen = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    last_seen = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)

    __table_args__ = (
        Index("ix_host_users_host_id", "host_id"),
        Index("ix_host_users_username", "username"),
    )

class Job(Base):
    __tablename__ = "jobs"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    job_key = Column(String, unique=True, nullable=False, index=True)
    created_by = Column(String, index=True)
    job_type = Column(String, nullable=False, index=True)
    payload = Column(JSON, nullable=False)
    selector = Column(JSON, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False, index=True)

class JobRun(Base):
    __tablename__ = "job_runs"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    job_id = Column(UUID(as_uuid=True), ForeignKey("jobs.id", ondelete="CASCADE"), nullable=False, index=True)
    agent_id = Column(String, nullable=False, index=True)
    status = Column(String, nullable=False, index=True)
    started_at = Column(DateTime(timezone=True))
    finished_at = Column(DateTime(timezone=True))
    exit_code = Column(Integer)
    stdout = Column(Text)
    stderr = Column(Text)
    error = Column(Text)
    __table_args__ = (UniqueConstraint("job_id","agent_id", name="uq_job_agent"),)

class HostLoadMetric(Base):
    __tablename__ = "host_load_metrics"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    agent_id = Column(String, nullable=False, index=True)
    load_1min = Column(String, nullable=False)  # Store as string to preserve precision
    load_5min = Column(String, nullable=False)
    load_15min = Column(String, nullable=False)
    recorded_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False, index=True)


class HostMetricsSnapshot(Base):
    __tablename__ = "host_metrics_snapshots"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    agent_id = Column(String, nullable=False, index=True)

    disk_percent_used = Column(String)  # keep as string for precision/backwards compat
    mem_percent_used = Column(String)
    load_1min = Column(String)
    vcpus = Column(Integer)

    recorded_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False, index=True)

    __table_args__ = (
        Index("ix_host_metrics_snapshots_agent_recorded", "agent_id", "recorded_at"),
    )


class AppUser(Base):
    __tablename__ = "app_users"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    username = Column(String, unique=True, nullable=False, index=True)
    password_hash = Column(String, nullable=False)
    role = Column(String, nullable=False, default="operator", index=True)  # admin|operator|readonly
    is_active = Column(Boolean, nullable=False, default=True)

    # MFA (TOTP)
    mfa_enabled = Column(Boolean, nullable=False, default=False)
    totp_secret_enc = Column(Text)  # Fernet-encrypted base32 secret
    totp_secret_pending_enc = Column(Text)  # pending enrollment secret
    mfa_enrolled_at = Column(DateTime(timezone=True))
    mfa_pending_at = Column(DateTime(timezone=True))
    # JSON list of hashed recovery codes (sha256)
    recovery_codes = Column(JSON, nullable=False, default=list)

    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

class AppSession(Base):
    __tablename__ = "app_sessions"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("app_users.id", ondelete="CASCADE"), nullable=False, index=True)
    token_sha256 = Column(String, unique=True, nullable=False, index=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False, index=True)

    # MFA gating: set once the user completes MFA for this session.
    mfa_verified_at = Column(DateTime(timezone=True))


class AnsibleRun(Base):
    __tablename__ = "ansible_runs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    run_key = Column(String, unique=True, nullable=False, index=True)

    playbook = Column(String, nullable=False, index=True)
    created_by = Column(String, nullable=True, index=True)

    # request metadata
    targets = Column(JSON, nullable=False, default=list)  # agent ids / host strings
    extra_vars = Column(JSON, nullable=False, default=dict)  # REDACTED vars only

    status = Column(String, nullable=False, index=True)  # running|success|failed
    rc = Column(Integer)

    stdout = Column(Text)
    stderr = Column(Text)

    log_name = Column(String)
    log_path = Column(String)

    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False, index=True)
    finished_at = Column(DateTime(timezone=True))


class PatchCampaign(Base):
    __tablename__ = "patch_campaigns"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    campaign_key = Column(String, unique=True, nullable=False, index=True)

    created_by = Column(String, nullable=True, index=True)
    kind = Column(String, nullable=False, index=True)  # e.g. "security-updates" (currently best-effort)

    selector = Column(JSON, nullable=False, default=dict)  # {agent_ids?:[], labels?:{}}
    rings = Column(JSON, nullable=False, default=list)  # [{name, agent_ids:[...]}]

    window_start = Column(DateTime(timezone=True), nullable=False, index=True)
    window_end = Column(DateTime(timezone=True), nullable=False, index=True)

    concurrency = Column(Integer, nullable=False, default=5)
    reboot_if_needed = Column(Boolean, nullable=False, default=False)
    include_kernel = Column(Boolean, nullable=False, default=False)

    status = Column(String, nullable=False, default="scheduled", index=True)  # scheduled|running|success|failed|canceled

    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False, index=True)
    started_at = Column(DateTime(timezone=True))
    finished_at = Column(DateTime(timezone=True))


class PatchCampaignHost(Base):
    __tablename__ = "patch_campaign_hosts"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    campaign_id = Column(UUID(as_uuid=True), ForeignKey("patch_campaigns.id", ondelete="CASCADE"), nullable=False, index=True)

    agent_id = Column(String, nullable=False, index=True)
    ring = Column(Integer, nullable=False, default=0, index=True)

    status = Column(String, nullable=False, default="queued", index=True)  # queued|running|success|failed|skipped

    job_key_upgrade = Column(String, index=True)
    job_key_reboot_check = Column(String, index=True)
    job_key_reboot = Column(String, index=True)

    reboot_required = Column(Boolean)

    error = Column(Text)

    started_at = Column(DateTime(timezone=True))
    finished_at = Column(DateTime(timezone=True))

    __table_args__ = (
        UniqueConstraint("campaign_id", "agent_id", name="uq_campaign_agent"),
        Index("ix_patch_campaign_hosts_campaign_ring", "campaign_id", "ring"),
    )


class AuditLog(Base):
    __tablename__ = "audit_log"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    actor = Column(String, nullable=True, index=True)
    action = Column(String, nullable=False, index=True)
    entity_type = Column(String, nullable=False, index=True)
    entity_key = Column(String, nullable=True, index=True)
    detail = Column(JSON, nullable=False, default=dict)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False, index=True)

class CronJob(Base):
    __tablename__ = "cron_jobs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("app_users.id", ondelete="CASCADE"), nullable=False, index=True)

    name = Column(String, nullable=False, default="")

    # when to run (UTC). Treat as one-shot for now.
    run_at = Column(DateTime(timezone=True), nullable=False, index=True)

    # what to do
    action = Column(String, nullable=False, index=True)  # dist-upgrade|inventory-now|security-campaign
    payload = Column(JSON, nullable=False, default=dict)

    # who to target
    selector = Column(JSON, nullable=False, default=dict)  # {agent_ids:[...]} (labels can be added later)

    status = Column(String, nullable=False, default="scheduled", index=True)  # scheduled|running|done|canceled|failed

    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False, index=True)
    started_at = Column(DateTime(timezone=True))
    finished_at = Column(DateTime(timezone=True))
    last_error = Column(Text)


class CronJobRun(Base):
    __tablename__ = "cron_job_runs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    cron_job_id = Column(UUID(as_uuid=True), ForeignKey("cron_jobs.id", ondelete="CASCADE"), nullable=False, index=True)

    job_key = Column(String, nullable=True, index=True)  # references jobs.job_key
    status = Column(String, nullable=False, default="queued", index=True)  # queued|running|success|failed

    started_at = Column(DateTime(timezone=True))
    finished_at = Column(DateTime(timezone=True))
    error = Column(Text)

    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False, index=True)

class UserSSHKey(Base):
    __tablename__ = "user_ssh_keys"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("app_users.id", ondelete="CASCADE"), nullable=False, index=True)

    name = Column(String, nullable=False, default="")
    public_key = Column(Text, nullable=False)
    fingerprint = Column(String, nullable=False, index=True)

    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False, index=True)
    revoked_at = Column(DateTime(timezone=True))

    __table_args__ = (Index("ix_user_ssh_keys_user_created", "user_id", "created_at"),)


class SSHKeyDeploymentRequest(Base):
    __tablename__ = "ssh_key_deployment_requests"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    user_id = Column(UUID(as_uuid=True), ForeignKey("app_users.id", ondelete="CASCADE"), nullable=False, index=True)
    key_id = Column(UUID(as_uuid=True), ForeignKey("user_ssh_keys.id", ondelete="CASCADE"), nullable=False, index=True)

    agent_ids = Column(JSON, nullable=False, default=list)
    status = Column(String, nullable=False, default="pending", index=True)  # pending|approved|rejected|done|failed

    approved_by = Column(String, nullable=True, index=True)
    approved_at = Column(DateTime(timezone=True))

    error = Column(Text)

    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False, index=True)
    finished_at = Column(DateTime(timezone=True))

    __table_args__ = (Index("ix_ssh_key_deploy_req_status", "status"),)


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    action = Column(String, nullable=False, index=True)

    actor_user_id = Column(UUID(as_uuid=True), ForeignKey("app_users.id", ondelete="SET NULL"), nullable=True, index=True)
    actor_username = Column(String, nullable=True, index=True)
    actor_role = Column(String, nullable=True, index=True)

    ip_address = Column(String, nullable=True)
    user_agent = Column(String, nullable=True)

    target_type = Column(String, nullable=True, index=True)
    target_id = Column(String, nullable=True, index=True)
    target_name = Column(String, nullable=True)

    meta = Column(JSON, nullable=False, default=dict)

    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False, index=True)

    __table_args__ = (
        Index("ix_audit_events_actor_created", "actor_user_id", "created_at"),
        Index("ix_audit_events_action_created", "action", "created_at"),
    )
