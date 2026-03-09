from __future__ import annotations

import logging
from datetime import datetime, time, timedelta, timezone
from zoneinfo import ZoneInfo

from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from ..config import settings
from ..db import SessionLocal
from ..models import AuditEvent, BackupVerificationPolicy, BackupVerificationRun
from .backup_verification import run_and_persist_backup_verification
from .db_utils import transaction
from .teams import post_teams_message

logger = logging.getLogger(__name__)


def _parse_hhmm(hhmm: str | None, default: time = time(3, 0)) -> time:
    raw = (hhmm or "").strip()
    if ":" not in raw:
        return default
    try:
        h, m = raw.split(":", 1)
        return time(hour=max(0, min(23, int(h))), minute=max(0, min(59, int(m))))
    except Exception:
        return default


def _next_run(now_utc: datetime, policy: BackupVerificationPolicy) -> datetime:
    tz_name = (policy.timezone or "UTC").strip() or "UTC"
    try:
        tz = ZoneInfo(tz_name)
    except Exception:
        tz = timezone.utc

    now_local = now_utc.astimezone(tz)
    tod = _parse_hhmm(policy.time_hhmm)

    if (policy.schedule_kind or "daily") == "weekly":
        target_wd = int(policy.weekday if policy.weekday is not None else 0)
        target_wd = max(0, min(6, target_wd))
        delta = (target_wd - now_local.weekday()) % 7
        cand = datetime(now_local.year, now_local.month, now_local.day, tod.hour, tod.minute, tzinfo=tz) + timedelta(days=delta)
        if cand <= now_local:
            cand = cand + timedelta(days=7)
        return cand.astimezone(timezone.utc)

    cand = datetime(now_local.year, now_local.month, now_local.day, tod.hour, tod.minute, tzinfo=tz)
    if cand <= now_local:
        cand = cand + timedelta(days=1)
    return cand.astimezone(timezone.utc)


def run_policy_tick_once(db: Session) -> None:
    now = datetime.now(timezone.utc)
    policy = db.execute(select(BackupVerificationPolicy).order_by(BackupVerificationPolicy.created_at.asc()).limit(1)).scalar_one_or_none()
    if not policy or not policy.enabled:
        return
    if not policy.next_run_at or policy.next_run_at > now:
        return

    with transaction(db):
        p = db.execute(select(BackupVerificationPolicy).where(BackupVerificationPolicy.id == policy.id)).scalar_one()
        if not p.enabled or not p.next_run_at or p.next_run_at > now:
            return
        # advance first to avoid duplicate dispatch
        p.next_run_at = _next_run(now, p)

    run_status = "failed"
    run_id = None
    err = None
    try:
        with transaction(db):
            row = run_and_persist_backup_verification(
                db,
                backup_path=p.backup_path,
                expected_sha256=p.expected_sha256,
                expected_schema_version=p.expected_schema_version,
                created_by="cron",
            )
            run_status = row.status
            run_id = str(row.id)
            p2 = db.execute(select(BackupVerificationPolicy).where(BackupVerificationPolicy.id == p.id)).scalar_one()
            p2.last_run_at = row.finished_at
            p2.last_status = row.status
            p2.last_error = None if row.status == "verified" else "verification failed"
            db.add(
                AuditEvent(
                    action="backup_verification.run",
                    actor_username="cron",
                    actor_role="system",
                    target_type="backup_verification_run",
                    target_id=str(row.id),
                    meta={"status": row.status, "trigger": "policy_schedule"},
                    created_at=now,
                )
            )
    except Exception as e:
        err = str(e)
        logger.exception("backup verification policy run failed")
        with transaction(db):
            p2 = db.execute(select(BackupVerificationPolicy).where(BackupVerificationPolicy.id == p.id)).scalar_one()
            p2.last_run_at = now
            p2.last_status = "failed"
            p2.last_error = err[:1000]

    # Alerts: failure and stale
    latest = db.execute(select(BackupVerificationRun).order_by(desc(BackupVerificationRun.finished_at)).limit(1)).scalar_one_or_none()
    stale = False
    if latest and latest.finished_at and p.stale_after_hours:
        stale_cutoff = now - timedelta(hours=int(p.stale_after_hours))
        stale = latest.finished_at < stale_cutoff

    should_alert_failure = bool(p.alert_on_failure and (run_status == "failed"))
    should_alert_stale = bool(p.alert_on_stale and stale)

    if should_alert_failure or should_alert_stale:
        webhook = (getattr(settings, "teams_webhook_url", None) or "").strip()
        if bool(getattr(settings, "teams_alerts_enabled", False)) and webhook:
            lines = [f"Policy: scheduled backup verification", f"Run status: {run_status}"]
            if run_id:
                lines.append(f"Run id: {run_id}")
            if err:
                lines.append(f"Error: {err[:300]}")
            if should_alert_stale:
                lines.append(f"Latest verification is stale (> {int(p.stale_after_hours)}h)")
            try:
                post_teams_message(webhook, "Backup verification alert", lines)
                with transaction(db):
                    p3 = db.execute(select(BackupVerificationPolicy).where(BackupVerificationPolicy.id == p.id)).scalar_one()
                    p3.last_alert_at = now
            except Exception:
                logger.exception("backup verification Teams alert failed")


def run_policy_tick_once_fresh_session() -> None:
    with SessionLocal() as db:
        run_policy_tick_once(db)
