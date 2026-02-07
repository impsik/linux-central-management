from __future__ import annotations

from datetime import datetime, timezone, timedelta, time

import calendar
from zoneinfo import ZoneInfo

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import get_db
from ..deps import require_ui_user
from ..models import CronJob, CronJobRun
from ..services.db_utils import transaction

router = APIRouter(prefix="/cronjobs", tags=["cronjobs"])


ALLOWED_ACTIONS = {"dist-upgrade", "inventory-now", "security-campaign"}


class CronJobCreate(BaseModel):
    name: str = Field(default="")
    run_at: str | None = None  # ISO string (UTC). Optional for recurring schedules.
    action: str
    agent_ids: list[str] = Field(default_factory=list)

    # scheduling (safe/quick): one-shot or simple recurrence
    schedule_kind: str = Field(default="once")  # once|daily|weekly|monthly
    timezone: str = Field(default="UTC")  # IANA tz name from browser

    # recurrence details (interpreted in user's timezone)
    time_hhmm: str | None = None  # e.g. "02:00" (for daily/weekly/monthly)
    weekday: int | None = None  # 0=Mon..6=Sun (weekly)
    day_of_month: int | None = None  # 1..31 (monthly)


@router.get("")
def list_cronjobs(db: Session = Depends(get_db), user=Depends(require_ui_user)):
    rows = (
        db.execute(
            select(CronJob)
            .where(CronJob.user_id == user.id, CronJob.status != "canceled")
            .order_by(CronJob.run_at.desc())
            .limit(200)
        )
        .scalars()
        .all()
    )

    items = []
    for c in rows:
        # one-shot for now: take most recent run
        last_run = (
            db.execute(
                select(CronJobRun)
                .where(CronJobRun.cron_job_id == c.id)
                .order_by(CronJobRun.created_at.desc())
                .limit(1)
            )
            .scalars()
            .first()
        )

        items.append(
            {
                "id": str(c.id),
                "name": c.name,
                "run_at": c.run_at.isoformat() if c.run_at else None,
                "action": c.action,
                "selector": c.selector,
                "status": c.status,
                "created_at": c.created_at.isoformat() if c.created_at else None,
                "last_error": c.last_error,
                "latest_run": (
                    {
                        "job_key": last_run.job_key,
                        "status": last_run.status,
                        "started_at": last_run.started_at.isoformat() if last_run.started_at else None,
                        "finished_at": last_run.finished_at.isoformat() if last_run.finished_at else None,
                        "error": last_run.error,
                    }
                    if last_run
                    else None
                ),
            }
        )

    return {"items": items}


@router.post("")
def create_cronjob(payload: CronJobCreate, db: Session = Depends(get_db), user=Depends(require_ui_user)):
    action = (payload.action or "").strip()
    if action not in ALLOWED_ACTIONS:
        raise HTTPException(400, "invalid action")

    # Scheduling
    schedule_kind = (payload.schedule_kind or "once").strip() or "once"
    tz_name = (payload.timezone or "UTC").strip() or "UTC"
    try:
        tz = ZoneInfo(tz_name)
    except Exception:
        tz = timezone.utc

    run_at: datetime | None = None

    if schedule_kind == "once":
        if not payload.run_at:
            raise HTTPException(400, "run_at is required for once")
        try:
            run_at = datetime.fromisoformat(payload.run_at.replace("Z", "+00:00"))
        except Exception:
            raise HTTPException(400, "invalid run_at")
        if run_at.tzinfo is None:
            run_at = run_at.replace(tzinfo=timezone.utc)
        run_at = run_at.astimezone(timezone.utc)

    else:
        # Recurring schedules: compute next occurrence from now in user's local time.
        now_utc = datetime.now(timezone.utc)
        now_local = now_utc.astimezone(tz)

        # Determine local time-of-day
        hhmm = (payload.time_hhmm or "").strip()
        if not hhmm or ":" not in hhmm:
            raise HTTPException(400, "time_hhmm is required for recurring schedules")
        try:
            hh, mm = hhmm.split(":", 1)
            tod = time(hour=max(0, min(23, int(hh))), minute=max(0, min(59, int(mm))))
        except Exception:
            raise HTTPException(400, "invalid time_hhmm")

        def _candidate_for_date(d):
            return datetime(d.year, d.month, d.day, tod.hour, tod.minute, 0, tzinfo=tz)

        if schedule_kind == "daily":
            cand = _candidate_for_date(now_local.date())
            if cand <= now_local:
                cand = _candidate_for_date(now_local.date() + timedelta(days=1))
            run_at = cand.astimezone(timezone.utc)

        elif schedule_kind == "weekly":
            if payload.weekday is None:
                raise HTTPException(400, "weekday is required for weekly")
            target_wd = int(payload.weekday)
            target_wd = max(0, min(6, target_wd))
            delta = (target_wd - now_local.weekday()) % 7
            cand_date = now_local.date() + timedelta(days=delta)
            cand = _candidate_for_date(cand_date)
            if cand <= now_local:
                cand = _candidate_for_date(cand_date + timedelta(days=7))
            run_at = cand.astimezone(timezone.utc)

        elif schedule_kind == "monthly":
            if payload.day_of_month is None:
                raise HTTPException(400, "day_of_month is required for monthly")
            dom = max(1, min(31, int(payload.day_of_month)))

            y = now_local.year
            m = now_local.month
            last_day = calendar.monthrange(y, m)[1]
            day = min(dom, last_day)
            cand = datetime(y, m, day, tod.hour, tod.minute, 0, tzinfo=tz)
            if cand <= now_local:
                # next month
                m += 1
                if m == 13:
                    m = 1
                    y += 1
                last_day = calendar.monthrange(y, m)[1]
                day = min(dom, last_day)
                cand = datetime(y, m, day, tod.hour, tod.minute, 0, tzinfo=tz)
            run_at = cand.astimezone(timezone.utc)

        else:
            raise HTTPException(400, "invalid schedule_kind")

    agent_ids = [a.strip() for a in (payload.agent_ids or []) if a and a.strip()]
    if not agent_ids:
        raise HTTPException(400, "select at least one host")

    with transaction(db):
        cj = CronJob(
            user_id=user.id,
            name=(payload.name or "").strip() or f"{action} ({len(agent_ids)} hosts)",
            run_at=run_at,
            action=action,
            payload={
                "schedule": {
                    "kind": (payload.schedule_kind or "once").strip(),
                    "timezone": (payload.timezone or "UTC").strip() or "UTC",
                    "time_hhmm": payload.time_hhmm,
                    "weekday": payload.weekday,
                    "day_of_month": payload.day_of_month,
                }
            },
            selector={"agent_ids": agent_ids},
            status="scheduled",
        )
        db.add(cj)

    return {"id": str(cj.id), "status": cj.status}


@router.post("/{cron_id}/cancel")
def cancel_cronjob(cron_id: str, db: Session = Depends(get_db), user=Depends(require_ui_user)):
    cj = db.execute(select(CronJob).where(CronJob.id == cron_id, CronJob.user_id == user.id)).scalar_one_or_none()
    if not cj:
        raise HTTPException(404, "unknown cronjob")

    if cj.status in ("done", "canceled"):
        return {"id": str(cj.id), "status": cj.status}

    with transaction(db):
        cj.status = "canceled"

    return {"id": str(cj.id), "status": cj.status}


@router.get("/{cron_id}/runs")
def cronjob_runs(cron_id: str, db: Session = Depends(get_db), user=Depends(require_ui_user)):
    cj = db.execute(select(CronJob).where(CronJob.id == cron_id, CronJob.user_id == user.id)).scalar_one_or_none()
    if not cj:
        raise HTTPException(404, "unknown cronjob")

    rows = (
        db.execute(select(CronJobRun).where(CronJobRun.cron_job_id == cj.id).order_by(CronJobRun.created_at.desc()))
        .scalars()
        .all()
    )

    return {
        "items": [
            {
                "id": str(r.id),
                "job_key": r.job_key,
                "status": r.status,
                "started_at": r.started_at.isoformat() if r.started_at else None,
                "finished_at": r.finished_at.isoformat() if r.finished_at else None,
                "error": r.error,
            }
            for r in rows
        ]
    }
