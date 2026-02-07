from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from ..config import settings
from ..db import SessionLocal
from ..models import Host, HostMetricsSnapshot
from ..services.db_utils import transaction
from ..services.jobs import create_job_with_runs, push_job_to_agents

logger = logging.getLogger(__name__)


async def metrics_refresh_loop(stop_event: asyncio.Event) -> None:
    """Periodically enqueue query-metrics jobs for online hosts.

    We store snapshots on job completion (see /agent/job-event handler), so this
    loop only needs to enqueue jobs.

    This keeps the Overview/Attention panel fresh even if nobody clicks hosts.
    """

    interval_s = int(getattr(settings, "metrics_background_refresh_seconds", 60) or 60)
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

        now = datetime.now(timezone.utc)
        grace_s = int(getattr(settings, "agent_online_grace_seconds", 10) or 10)
        online_cutoff = now.timestamp() - grace_s

        # Only refresh hosts that don't have a recent snapshot.
        fresh_cutoff = now - timedelta(seconds=max(30, interval_s))

        db = SessionLocal()
        try:
            # Online hosts
            hosts = (
                db.execute(
                    select(Host)
                    .where(Host.last_seen.is_not(None))
                    .where(Host.last_seen >= datetime.fromtimestamp(online_cutoff, tz=timezone.utc))
                    .order_by(Host.hostname.asc())
                    .limit(batch_limit)
                )
                .scalars()
                .all()
            )

            if not hosts:
                continue

            recent = set(
                db.execute(
                    select(HostMetricsSnapshot.agent_id)
                    .where(HostMetricsSnapshot.recorded_at >= fresh_cutoff)
                )
                .scalars()
                .all()
            )

            agent_ids = [h.agent_id for h in hosts if h.agent_id and h.agent_id not in recent]
            if not agent_ids:
                continue

            with transaction(db):
                created = create_job_with_runs(
                    db=db,
                    job_type="query-metrics",
                    payload={"source": "metrics_refresh_loop"},
                    agent_ids=agent_ids,
                    commit=False,
                )

            await push_job_to_agents(
                agent_ids=agent_ids,
                job_payload_builder=lambda aid: {"job_id": created.job_key, "type": "query-metrics"},
            )

        except Exception:
            logger.exception("metrics_refresh_loop tick failed")
        finally:
            try:
                db.close()
            except Exception:
                pass
