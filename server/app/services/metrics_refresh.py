from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import case, func, or_, select

from ..config import settings
from ..db import SessionLocal
from ..models import Host, HostMetricsSnapshot, Job, JobRun
from ..services.background import run_blocking
from ..services.db_utils import transaction
from ..services.jobs import create_job_with_runs, push_job_to_agents

logger = logging.getLogger(__name__)


def _queue_metrics_refresh(*, interval_s: int, batch_limit: int, now: datetime | None = None) -> tuple[list[str], str] | None:
    """Select due hosts and persist one batch using a session owned by this thread."""
    now = now or datetime.now(timezone.utc)
    grace_s = int(getattr(settings, "agent_online_grace_seconds", 30) or 30)
    online = (
        Host.last_seen.is_not(None),
        Host.last_seen >= now - timedelta(seconds=grace_s),
        Host.agent_id.is_not(None),
        Host.agent_id != "",
    )
    fresh_cutoff = now - timedelta(seconds=max(30, interval_s))

    with SessionLocal() as db:
        online_count = db.execute(select(func.count()).select_from(Host).where(*online)).scalar_one()
        if not online_count:
            return None

        # Keep failed requests from repeatedly taking the first batch when they
        # never produce a snapshot. Only inspect recent attempts covering a full
        # fleet rotation; don't aggregate the entire retained job history.
        rotation_ticks = (online_count + batch_limit - 1) // batch_limit
        attempt_cutoff = now - timedelta(seconds=max(30, interval_s) * (rotation_ticks + 1))
        attempts = (
            select(JobRun.agent_id, func.max(Job.created_at).label("requested_at"))
            .join(Job, Job.id == JobRun.job_id)
            .where(Job.job_type == "query-metrics", Job.created_at >= attempt_cutoff)
            .group_by(JobRun.agent_id)
            .subquery()
        )
        # The (agent_id, recorded_at) index finds one latest sample per host
        # without grouping every retained metrics row on every tick.
        latest_snapshot = (
            select(HostMetricsSnapshot.recorded_at)
            .where(HostMetricsSnapshot.agent_id == Host.agent_id)
            .order_by(HostMetricsSnapshot.recorded_at.desc())
            .limit(1)
            .correlate(Host)
            .scalar_subquery()
        )
        pending = (
            select(JobRun.id)
            .join(Job, Job.id == JobRun.job_id)
            .where(
                JobRun.agent_id == Host.agent_id,
                JobRun.status.in_(("queued", "running")),
                Job.job_type == "query-metrics",
            )
            .correlate(Host)
            .exists()
        )
        candidates = (
            select(
                Host.agent_id,
                Host.hostname,
                latest_snapshot.label("recorded_at"),
                attempts.c.requested_at,
            )
            .outerjoin(attempts, attempts.c.agent_id == Host.agent_id)
            .where(*online, ~pending)
            .subquery()
        )
        # Never sampled/requested hosts come first; otherwise use the latest
        # sample or request as the fairness clock, including failed attempts.
        priority = case(
            (candidates.c.requested_at.is_(None), candidates.c.recorded_at),
            (candidates.c.recorded_at.is_(None), candidates.c.requested_at),
            (candidates.c.requested_at > candidates.c.recorded_at, candidates.c.requested_at),
            else_=candidates.c.recorded_at,
        )
        agent_ids = db.execute(
            select(candidates.c.agent_id)
            .where(or_(candidates.c.recorded_at.is_(None), candidates.c.recorded_at < fresh_cutoff))
            .order_by(priority.asc().nulls_first(), candidates.c.hostname.asc(), candidates.c.agent_id.asc())
            .limit(batch_limit)
        ).scalars().all()
        if not agent_ids:
            return None

        with transaction(db):
            created = create_job_with_runs(
                db=db,
                job_type="query-metrics",
                payload={"source": "metrics_refresh_loop"},
                agent_ids=agent_ids,
                commit=False,
            )
        return agent_ids, created.job_key


async def _refresh_metrics_once(*, interval_s: int, batch_limit: int) -> None:
    batch = await run_blocking(_queue_metrics_refresh, interval_s=interval_s, batch_limit=batch_limit)
    if batch is None:
        return
    agent_ids, job_key = batch
    # Only the in-memory asyncio dispatcher belongs on the API event loop.
    # If interrupted here, the committed durable job is still found by polling.
    await push_job_to_agents(
        agent_ids=agent_ids,
        job_payload_builder=lambda aid: {"job_id": job_key, "type": "query-metrics"},
    )


async def metrics_refresh_loop(stop_event: asyncio.Event) -> None:
    """Periodically enqueue query-metrics jobs for online hosts.

    We store snapshots on job completion (see /agent/job-event handler), so this
    loop only needs to enqueue jobs.

    This keeps the Overview/Attention panel fresh even if nobody clicks hosts.
    """

    configured_interval = getattr(settings, "metrics_background_refresh_seconds", 60)
    interval_s = int(60 if configured_interval is None else configured_interval)
    if interval_s <= 0:
        logger.info("Metrics refresh loop disabled (metrics_background_refresh_seconds<=0)")
        return

    batch_limit = int(getattr(settings, "metrics_background_batch_limit", 50) or 50)
    if batch_limit < 1:
        batch_limit = 1
    if batch_limit > 200:
        batch_limit = 200

    logger.info(f"Started metrics refresh loop (every {interval_s}s, batch_limit={batch_limit})")

    while not stop_event.is_set():
        try:
            # Sleep first to avoid spiking right at boot.
            await asyncio.wait_for(stop_event.wait(), timeout=interval_s)
            break
        except asyncio.TimeoutError:
            pass

        try:
            await _refresh_metrics_once(interval_s=interval_s, batch_limit=batch_limit)
        except Exception:
            logger.exception("metrics_refresh_loop tick failed")
