from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
import logging

from sqlalchemy import String, cast, delete, exists, or_, select, text

from ..config import settings
from ..db import Base, SessionLocal
from ..models import AuditEvent, AuditLog, CronJobRun, HighRiskActionRequest, Job, JobRun, PatchCampaignHost
from .background import run_blocking

logger = logging.getLogger(__name__)


def _unreferenced_job_conditions():
    """Keep jobs used by workflows or audit history, including non-FK links."""
    conditions = [
        ~exists(select(CronJobRun.id).where(CronJobRun.job_key == Job.job_key)),
        ~exists(select(PatchCampaignHost.id).where(or_(
            PatchCampaignHost.job_key_upgrade == Job.job_key,
            PatchCampaignHost.job_key_reboot_check == Job.job_key,
            PatchCampaignHost.job_key_reboot == Job.job_key,
        ))),
        ~exists(select(HighRiskActionRequest.id).where(HighRiskActionRequest.execution_ref == Job.job_key)),
        ~exists(select(AuditEvent.id).where(or_(
            AuditEvent.target_id == Job.job_key,
            AuditEvent.target_id == cast(Job.id, String),
        ))),
        ~exists(select(AuditLog.id).where(or_(
            AuditLog.entity_key == Job.job_key,
            AuditLog.entity_key == cast(Job.id, String),
        ))),
    ]
    # JobRun is the only current FK to Job. Protect any additional referencing
    # models introduced later, even if their foreign key uses ON DELETE CASCADE.
    for table in Base.metadata.tables.values():
        if table is JobRun.__table__:
            continue
        for fk in table.foreign_keys:
            if fk.column is Job.__table__.c.id:
                conditions.append(~exists(select(1).select_from(table).where(fk.parent == Job.id)))
    return conditions


def cleanup_metrics_job_history(*, now: datetime | None = None) -> dict[str, int]:
    """Delete one bounded batch of old successful automatic metrics results.

    A session is created inside the worker thread. Manual queries, failed and
    unfinished runs, cached metrics, and workflow/audit history are retained.
    """
    stats = {"job_runs_deleted": 0, "jobs_deleted": 0}
    days = int(settings.metrics_job_retention_days)
    if days <= 0:
        return stats
    batch_size = min(5000, max(1, int(settings.metrics_job_cleanup_batch_size)))
    cutoff = (now or datetime.now(timezone.utc)) - timedelta(days=days)

    with SessionLocal() as db, db.begin():
        if db.bind.dialect.name == "postgresql":
            # Bound database work and avoid overlapping cleanup across workers.
            db.execute(text("SET LOCAL statement_timeout = '5s'"))
            db.execute(text("SET LOCAL lock_timeout = '1s'"))
            if not db.execute(text("SELECT pg_try_advisory_xact_lock(1279479122)")).scalar_one():
                return stats

        eligible_jobs = [
            Job.job_type == "query-metrics",
            Job.created_by == "api",
            Job.payload["source"].as_string() == "metrics_refresh_loop",
            *_unreferenced_job_conditions(),
        ]
        rows = db.execute(
            select(JobRun.id, JobRun.job_id)
            .join(Job, Job.id == JobRun.job_id)
            .where(*eligible_jobs, JobRun.status == "success", JobRun.finished_at < cutoff)
            .order_by(JobRun.finished_at, JobRun.id)
            .limit(batch_size)
            .with_for_update(of=JobRun, skip_locked=True)
        ).all()
        if not rows:
            return stats

        # Recheck terminal state in the delete as well; never cascade through a
        # parent that still has a failed, active, or newer successful run.
        stats["job_runs_deleted"] = db.execute(
            delete(JobRun).where(
                JobRun.id.in_([row.id for row in rows]),
                JobRun.status == "success",
                JobRun.finished_at < cutoff,
            ).execution_options(synchronize_session=False)
        ).rowcount
        stats["jobs_deleted"] = db.execute(
            delete(Job).where(
                Job.id.in_({row.job_id for row in rows}),
                *eligible_jobs,
                ~exists(select(JobRun.id).where(JobRun.job_id == Job.id)),
            ).execution_options(synchronize_session=False)
        ).rowcount

    return stats


async def job_retention_loop(stop_event: asyncio.Event) -> None:
    interval = int(settings.metrics_job_cleanup_interval_seconds)
    if int(settings.metrics_job_retention_days) <= 0 or interval <= 0:
        logger.info("Automatic metrics job history cleanup disabled")
        return

    while not stop_event.is_set():
        try:
            # Delay the first batch to avoid competing with startup work.
            await asyncio.wait_for(stop_event.wait(), timeout=interval)
            return
        except asyncio.TimeoutError:
            pass
        try:
            stats = await run_blocking(cleanup_metrics_job_history)
            if stats["job_runs_deleted"]:
                logger.info("Removed old automatic metrics history: %s", stats)
        except Exception:
            logger.exception("Automatic metrics job history cleanup failed; retrying next interval")
