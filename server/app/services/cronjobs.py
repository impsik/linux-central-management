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
from .backup_verification_policy import run_policy_tick_once
from .db_utils import transaction
from .jobs import create_job_with_runs, push_job_to_agents

logger = logging.getLogger(__name__)

MISSED_RECURRING_GRACE = timedelta(minutes=15)


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
        # Backup verification policy scheduler piggybacks on cron tick loop.
        run_policy_tick_once(db)

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

    if _is_missed_recurring_run(cj, now):
        missed_run_at = cj.run_at
        next_run_at = _next_recurring_run_at(cj, after=now)
        done_at = datetime.now(timezone.utc)
        with transaction(db):
            cj = db.execute(select(CronJob).where(CronJob.id == cj.id)).scalar_one()
            if cj.status != "scheduled":
                return
            run = CronJobRun(
                cron_job_id=cj.id,
                status="skipped",
                started_at=done_at,
                finished_at=done_at,
                error="missed scheduled time; skipped catch-up run",
            )
            db.add(run)
            if next_run_at is not None:
                cj.run_at = next_run_at
                cj.status = "scheduled"
                cj.started_at = None
                cj.finished_at = None
                cj.last_error = None
            else:
                cj.status = "done"
                cj.finished_at = done_at
        logger.warning(
            "Skipped missed recurring cronjob %s scheduled for %s; next_run_at=%s",
            getattr(cj, "id", None),
            missed_run_at,
            next_run_at,
        )
        return

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
                created_updates = create_job_with_runs(
                    db=db,
                    job_type="query-pkg-updates",
                    payload={"refresh": True},
                    agent_ids=agent_ids,
                    commit=False,
                )
                run.job_key = created.job_key

            await push_job_to_agents(
                agent_ids=agent_ids,
                job_payload_builder=lambda aid: {"job_id": created.job_key, "type": "inventory-now"},
            )
            await push_job_to_agents(
                agent_ids=agent_ids,
                job_payload_builder=lambda aid: {
                    "job_id": created_updates.job_key,
                    "type": "query-pkg-updates",
                    "refresh": True,
                },
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
                    labels=None,
                    agent_ids=agent_ids,
                    rings=None,
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

        next_run_at = _next_recurring_run_at(cj, after=done_at)

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


def _schedule_payload(cj: CronJob) -> dict | None:
    schedule = (cj.payload or {}).get("schedule") if isinstance(cj.payload, dict) else None
    return schedule if isinstance(schedule, dict) else None


def _recurring_kind(cj: CronJob) -> str | None:
    schedule = _schedule_payload(cj)
    kind = (schedule or {}).get("kind")
    kind = str(kind or "").strip().lower()
    return kind if kind and kind != "once" else None


def _cron_timezone(schedule: dict | None):
    tz_name = str((schedule or {}).get("timezone") or "UTC")
    try:
        return ZoneInfo(tz_name)
    except Exception:
        return timezone.utc


def _cron_time_of_day(cj: CronJob, schedule: dict | None, tz) -> time:
    hhmm = (schedule or {}).get("time_hhmm") or None
    if hhmm and isinstance(hhmm, str) and ":" in hhmm:
        try:
            hh, mm = hhmm.split(":", 1)
            hh_i = int(hh)
            mm_i = int(mm)
            return time(hour=max(0, min(23, hh_i)), minute=max(0, min(59, mm_i)))
        except Exception:
            pass
    return cj.run_at.astimezone(tz).timetz().replace(tzinfo=None)


def _next_recurring_candidate(cj: CronJob) -> datetime | None:
    schedule = _schedule_payload(cj)
    kind = _recurring_kind(cj)
    if not kind:
        return None

    tz = _cron_timezone(schedule)
    tod = _cron_time_of_day(cj, schedule, tz)
    last_local = cj.run_at.astimezone(tz)

    if kind == "daily":
        nxt_date = last_local.date() + timedelta(days=1)
        next_local = datetime.combine(nxt_date, tod, tzinfo=tz)
        return next_local.astimezone(timezone.utc)

    if kind == "weekly":
        wd = (schedule or {}).get("weekday")
        try:
            target_wd = int(wd)
        except Exception:
            target_wd = last_local.weekday()
        delta = (target_wd - last_local.weekday()) % 7
        if delta == 0:
            delta = 7
        nxt_date = last_local.date() + timedelta(days=delta)
        next_local = datetime.combine(nxt_date, tod, tzinfo=tz)
        return next_local.astimezone(timezone.utc)

    if kind == "monthly":
        dom = (schedule or {}).get("day_of_month")
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
        return next_local.astimezone(timezone.utc)

    return None


def _next_recurring_run_at(cj: CronJob, *, after: datetime) -> datetime | None:
    if after.tzinfo is None:
        after = after.replace(tzinfo=timezone.utc)
    else:
        after = after.astimezone(timezone.utc)

    next_run_at = _next_recurring_candidate(cj)
    guard = 0
    original_run_at = cj.run_at
    try:
        while next_run_at is not None and next_run_at <= after:
            cj.run_at = next_run_at
            next_run_at = _next_recurring_candidate(cj)
            guard += 1
            if guard > 400:
                raise RuntimeError("recurring cron next-run calculation exceeded guard limit")
    finally:
        cj.run_at = original_run_at
    return next_run_at


def _is_missed_recurring_run(cj: CronJob, now: datetime) -> bool:
    if not _recurring_kind(cj):
        return False
    run_at = cj.run_at
    if run_at.tzinfo is None:
        run_at = run_at.replace(tzinfo=timezone.utc)
    return now > run_at.astimezone(timezone.utc) + MISSED_RECURRING_GRACE
