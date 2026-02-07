from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone, timedelta, time

import calendar
from zoneinfo import ZoneInfo

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import SessionLocal
from ..models import CronJob, CronJobRun
from .db_utils import transaction
from .jobs import create_job_with_runs, push_job_to_agents

logger = logging.getLogger(__name__)


async def cronjob_loop(stop_event: asyncio.Event, *, tick_s: float = 2.0) -> None:
    """Background loop that dispatches one-shot cron jobs."""

    while not stop_event.is_set():
        try:
            await _run_tick()
        except Exception:
            logger.exception("cronjob tick failed")
        await asyncio.sleep(tick_s)


async def _run_tick() -> None:
    now = datetime.now(timezone.utc)

    with SessionLocal() as db:
        # Find due scheduled jobs
        due = (
            db.execute(
                select(CronJob)
                .where(
                    CronJob.status == "scheduled",
                    CronJob.run_at <= now,
                )
                .order_by(CronJob.run_at.asc())
                .limit(20)
            )
            .scalars()
            .all()
        )

        for cj in due:
            await _dispatch_one(db, cj)


async def _dispatch_one(db: Session, cj: CronJob) -> None:
    now = datetime.now(timezone.utc)

    # best-effort lock by flipping status inside a transaction
    with transaction(db):
        cj = db.execute(select(CronJob).where(CronJob.id == cj.id)).scalar_one()
        if cj.status != "scheduled":
            return
        cj.status = "running"
        cj.started_at = now
        cj.last_error = None

        run = CronJobRun(cron_job_id=cj.id, status="running", started_at=now)
        db.add(run)
        db.flush()

    action = cj.action
    agent_ids = (cj.selector or {}).get("agent_ids") or []
    agent_ids = [str(a) for a in agent_ids if a]

    try:
        if action == "dist-upgrade":
            with transaction(db):
                created = create_job_with_runs(
                    db=db,
                    job_type="dist-upgrade",
                    payload={},
                    agent_ids=agent_ids,
                    commit=False,
                )
                run.job_key = created.job_key

            await push_job_to_agents(
                agent_ids=agent_ids,
                job_payload_builder=lambda aid: {"job_id": created.job_key, "type": "dist-upgrade"},
            )

        elif action == "inventory-now":
            with transaction(db):
                created = create_job_with_runs(
                    db=db,
                    job_type="inventory-now",
                    payload={},
                    agent_ids=agent_ids,
                    commit=False,
                )
                run.job_key = created.job_key

            await push_job_to_agents(
                agent_ids=agent_ids,
                job_payload_builder=lambda aid: {"job_id": created.job_key, "type": "inventory-now"},
            )

        elif action == "security-campaign":
            # Use the existing patching API semantics: 1h window starting now.
            from ..services.patching import create_patch_campaign

            window_start = now
            window_end = now + timedelta(hours=1)

            with transaction(db):
                campaign = create_patch_campaign(
                    db=db,
                    kind="security-updates",
                    selector={"agent_ids": agent_ids},
                    window_start=window_start,
                    window_end=window_end,
                    concurrency=5,
                    reboot_if_needed=True,
                    include_kernel=False,
                    created_by="cron",
                )
                run.job_key = f"patch-campaign:{campaign.campaign_key}"

        else:
            raise RuntimeError(f"unsupported action {action}")

        done_at = datetime.now(timezone.utc)

        # If recurring schedule is set, compute next run_at (in user's local time)
        schedule = (cj.payload or {}).get('schedule') if isinstance(cj.payload, dict) else None
        kind = (schedule or {}).get('kind') if isinstance(schedule, dict) else None
        tz_name = (schedule or {}).get('timezone') if isinstance(schedule, dict) else 'UTC'
        tz_name = str(tz_name or 'UTC')

        next_run_at = None
        if kind and kind != 'once':
            try:
                tz = ZoneInfo(tz_name)
            except Exception:
                tz = timezone.utc

            # Determine local time-of-day
            hhmm = (schedule or {}).get('time_hhmm') or None
            if hhmm and isinstance(hhmm, str) and ':' in hhmm:
                try:
                    hh, mm = hhmm.split(':', 1)
                    hh_i = int(hh); mm_i = int(mm)
                    tod = time(hour=max(0, min(23, hh_i)), minute=max(0, min(59, mm_i)))
                except Exception:
                    tod = cj.run_at.astimezone(tz).timetz().replace(tzinfo=None)
            else:
                # default: use the originally scheduled local time-of-day
                tod = cj.run_at.astimezone(tz).timetz().replace(tzinfo=None)

            last_local = cj.run_at.astimezone(tz)

            if kind == 'daily':
                nxt_date = last_local.date() + timedelta(days=1)
                next_local = datetime.combine(nxt_date, tod, tzinfo=tz)
                next_run_at = next_local.astimezone(timezone.utc)

            elif kind == 'weekly':
                wd = (schedule or {}).get('weekday')
                try:
                    target_wd = int(wd)
                except Exception:
                    target_wd = last_local.weekday()
                delta = (target_wd - last_local.weekday()) % 7
                if delta == 0:
                    delta = 7
                nxt_date = last_local.date() + timedelta(days=delta)
                next_local = datetime.combine(nxt_date, tod, tzinfo=tz)
                next_run_at = next_local.astimezone(timezone.utc)

            elif kind == 'monthly':
                dom = (schedule or {}).get('day_of_month')
                try:
                    dom_i = int(dom)
                except Exception:
                    dom_i = last_local.day
                dom_i = max(1, min(31, dom_i))

                y = last_local.year
                m = last_local.month + 1
                if m == 13:
                    m = 1
                    y += 1
                last_day = calendar.monthrange(y, m)[1]
                day = min(dom_i, last_day)
                next_local = datetime(y, m, day, tod.hour, tod.minute, 0, tzinfo=tz)
                next_run_at = next_local.astimezone(timezone.utc)

        with transaction(db):
            cj = db.execute(select(CronJob).where(CronJob.id == cj.id)).scalar_one()
            run2 = db.execute(select(CronJobRun).where(CronJobRun.id == run.id)).scalar_one()
            run2.status = "success"
            run2.finished_at = done_at

            if next_run_at is not None:
                cj.status = "scheduled"
                cj.run_at = next_run_at
                cj.started_at = None
                cj.finished_at = None
            else:
                cj.status = "done"
                cj.finished_at = done_at

    except Exception as e:
        done_at = datetime.now(timezone.utc)
        with transaction(db):
            cj = db.execute(select(CronJob).where(CronJob.id == cj.id)).scalar_one()
            cj.status = "failed"
            cj.finished_at = done_at
            cj.last_error = str(e)
            run2 = db.execute(select(CronJobRun).where(CronJobRun.id == run.id)).scalar_one()
            run2.status = "failed"
            run2.finished_at = done_at
            run2.error = str(e)
        raise
