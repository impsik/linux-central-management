from __future__ import annotations

import csv
import io
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy import Integer, cast, func, select
from sqlalchemy.orm import Session

from ..config import settings
from ..db import get_db
from ..deps import require_admin_user, require_ui_user
from ..models import Host, HostMetricsSnapshot, HostPackageUpdate, Job, JobRun, NotificationDedupeState, OIDCAuthEvent
from ..services.db_utils import transaction
from ..services.jobs import create_job_with_runs, push_job_to_agents
from ..services.maintenance import is_within_maintenance_window
from ..services.teams import post_teams_message
from ..services.user_scopes import is_host_visible_to_user

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get("/summary")
def dashboard_summary(db: Session = Depends(get_db), user=Depends(require_ui_user)):
    """Fleet overview KPIs for the UI landing page."""

    now = datetime.now(timezone.utc)
    grace_s = int(getattr(settings, "agent_online_grace_seconds", 10) or 10)
    online_cutoff = now.timestamp() - grace_s

    # total hosts
    total_hosts = int(db.execute(select(func.count()).select_from(Host)).scalar_one() or 0)

    # online hosts (last_seen within grace)
    online_hosts = int(
        db.execute(
            select(func.count())
            .select_from(Host)
            .where(Host.last_seen.is_not(None), func.extract("epoch", Host.last_seen) >= online_cutoff)
        ).scalar_one()
        or 0
    )

    # updates
    total_updates = int(
        db.execute(
            select(func.count())
            .select_from(HostPackageUpdate)
            .where(HostPackageUpdate.update_available == True)  # noqa: E712
        ).scalar_one()
        or 0
    )

    hosts_with_updates = int(
        db.execute(
            select(func.count(func.distinct(HostPackageUpdate.host_id)))
            .select_from(HostPackageUpdate)
            .where(HostPackageUpdate.update_available == True)  # noqa: E712
        ).scalar_one()
        or 0
    )

    security_updates = int(
        db.execute(
            select(func.count())
            .select_from(HostPackageUpdate)
            .where(
                HostPackageUpdate.update_available == True,  # noqa: E712
                HostPackageUpdate.is_security == True,  # noqa: E712
            )
        ).scalar_one()
        or 0
    )

    hosts_with_security_updates = int(
        db.execute(
            select(func.count(func.distinct(HostPackageUpdate.host_id)))
            .select_from(HostPackageUpdate)
            .where(
                HostPackageUpdate.update_available == True,  # noqa: E712
                HostPackageUpdate.is_security == True,  # noqa: E712
            )
        ).scalar_one()
        or 0
    )

    freshest_updates_check = db.execute(select(func.max(HostPackageUpdate.checked_at))).scalar_one()

    # failed runs (last 24h)
    failed_runs_24h = int(
        db.execute(
            select(func.count())
            .select_from(JobRun)
            .where(
                JobRun.status == "failed",
                JobRun.finished_at.is_not(None),
                JobRun.finished_at >= (now - timedelta(hours=24)),
            )
        ).scalar_one()
        or 0
    )

    reboot_required_hosts = int(
        db.execute(select(func.count()).select_from(Host).where(Host.reboot_required == True))  # noqa: E712
        .scalar_one()
        or 0
    )

    return {
        "ts": now.isoformat(),
        "hosts": {
            "total": total_hosts,
            "online": online_hosts,
            "offline": max(0, total_hosts - online_hosts),
            "online_grace_seconds": grace_s,
            "reboot_required": reboot_required_hosts,
        },
        "updates": {
            "total": total_updates,
            "hosts_with_updates": hosts_with_updates,
            "security_total": security_updates,
            "hosts_with_security_updates": hosts_with_security_updates,
            "freshest_checked_at": freshest_updates_check,
        },
        "jobs": {"failed_runs_last_24h": failed_runs_24h},
        "notes": [],
    }


def _median(values: list[float]) -> float | None:
    if not values:
        return None
    vals = sorted(values)
    n = len(vals)
    mid = n // 2
    if n % 2 == 1:
        return float(vals[mid])
    return float((vals[mid - 1] + vals[mid]) / 2.0)


def _slo_window_metrics(db: Session, *, start: datetime, end: datetime, now_for_offline: datetime) -> dict:
    comp = db.execute(
        select(func.count())
        .select_from(JobRun)
        .where(JobRun.finished_at.is_not(None), JobRun.finished_at >= start, JobRun.finished_at < end, JobRun.status.in_(["success", "failed"]))
    ).scalar_one()
    succ = db.execute(
        select(func.count())
        .select_from(JobRun)
        .where(JobRun.finished_at.is_not(None), JobRun.finished_at >= start, JobRun.finished_at < end, JobRun.status == "success")
    ).scalar_one()
    success_rate = (float(succ) / float(comp) * 100.0) if comp else None

    patch_rows = db.execute(
        select(JobRun.started_at, JobRun.finished_at)
        .join(Job, Job.id == JobRun.job_id)
        .where(
            Job.job_type.in_(["pkg-upgrade", "dist-upgrade"]),
            JobRun.started_at.is_not(None),
            JobRun.finished_at.is_not(None),
            JobRun.finished_at >= start,
            JobRun.finished_at < end,
        )
    ).all()
    patch_durations = [max(0.0, (r[1] - r[0]).total_seconds()) for r in patch_rows if r[0] and r[1]]
    median_patch = _median(patch_durations)

    oidc_total = db.execute(
        select(func.count()).select_from(OIDCAuthEvent).where(OIDCAuthEvent.created_at >= start, OIDCAuthEvent.created_at < end)
    ).scalar_one()
    oidc_err = db.execute(
        select(func.count()).select_from(OIDCAuthEvent).where(
            OIDCAuthEvent.created_at >= start, OIDCAuthEvent.created_at < end, OIDCAuthEvent.status == "error"
        )
    ).scalar_one()
    auth_err_rate = (float(oidc_err) / float(oidc_total) * 100.0) if oidc_total else None

    grace_s = int(getattr(settings, "agent_online_grace_seconds", 10) or 10)
    online_cutoff = now_for_offline.timestamp() - grace_s
    total_hosts = int(db.execute(select(func.count()).select_from(Host)).scalar_one() or 0)
    online_hosts = int(
        db.execute(
            select(func.count())
            .select_from(Host)
            .where(Host.last_seen.is_not(None), func.extract("epoch", Host.last_seen) >= online_cutoff)
        ).scalar_one()
        or 0
    )
    offline_ratio = (float(max(0, total_hosts - online_hosts)) / float(total_hosts) * 100.0) if total_hosts else None

    return {
        "job_success_rate": {"value": success_rate, "sample_count": int(comp or 0)},
        "median_patch_duration": {"value": median_patch, "sample_count": len(patch_durations)},
        "auth_error_rate": {"value": auth_err_rate, "sample_count": int(oidc_total or 0)},
        "offline_host_ratio": {"value": offline_ratio, "sample_count": int(total_hosts or 0)},
    }


@router.get("/slo")
def dashboard_slo(
    hours: int = Query(24, ge=1, le=24 * 30),
    db: Session = Depends(get_db),
    user=Depends(require_ui_user),
):
    now = datetime.now(timezone.utc)
    start = now - timedelta(hours=hours)
    prev_start = start - timedelta(hours=hours)

    # Job success rate for completed runs.
    comp_now = db.execute(
        select(func.count())
        .select_from(JobRun)
        .where(JobRun.finished_at.is_not(None), JobRun.finished_at >= start, JobRun.status.in_(["success", "failed"]))
    ).scalar_one()
    succ_now = db.execute(
        select(func.count())
        .select_from(JobRun)
        .where(JobRun.finished_at.is_not(None), JobRun.finished_at >= start, JobRun.status == "success")
    ).scalar_one()

    comp_prev = db.execute(
        select(func.count())
        .select_from(JobRun)
        .where(
            JobRun.finished_at.is_not(None),
            JobRun.finished_at >= prev_start,
            JobRun.finished_at < start,
            JobRun.status.in_(["success", "failed"]),
        )
    ).scalar_one()
    succ_prev = db.execute(
        select(func.count())
        .select_from(JobRun)
        .where(JobRun.finished_at.is_not(None), JobRun.finished_at >= prev_start, JobRun.finished_at < start, JobRun.status == "success")
    ).scalar_one()

    success_rate_now = (float(succ_now) / float(comp_now) * 100.0) if comp_now else None
    success_rate_prev = (float(succ_prev) / float(comp_prev) * 100.0) if comp_prev else None

    # Median patch duration (seconds): pkg-upgrade + dist-upgrade runs in current/previous window.
    patch_now_rows = db.execute(
        select(JobRun.started_at, JobRun.finished_at)
        .join(Job, Job.id == JobRun.job_id)
        .where(
            Job.job_type.in_(["pkg-upgrade", "dist-upgrade"]),
            JobRun.started_at.is_not(None),
            JobRun.finished_at.is_not(None),
            JobRun.finished_at >= start,
        )
    ).all()
    patch_prev_rows = db.execute(
        select(JobRun.started_at, JobRun.finished_at)
        .join(Job, Job.id == JobRun.job_id)
        .where(
            Job.job_type.in_(["pkg-upgrade", "dist-upgrade"]),
            JobRun.started_at.is_not(None),
            JobRun.finished_at.is_not(None),
            JobRun.finished_at >= prev_start,
            JobRun.finished_at < start,
        )
    ).all()

    patch_now_durations = [max(0.0, (r[1] - r[0]).total_seconds()) for r in patch_now_rows if r[0] and r[1]]
    patch_prev_durations = [max(0.0, (r[1] - r[0]).total_seconds()) for r in patch_prev_rows if r[0] and r[1]]

    median_patch_now = _median(patch_now_durations)
    median_patch_prev = _median(patch_prev_durations)

    # Auth error rate from OIDC auth event stream.
    oidc_total_now = db.execute(
        select(func.count()).select_from(OIDCAuthEvent).where(OIDCAuthEvent.created_at >= start)
    ).scalar_one()
    oidc_err_now = db.execute(
        select(func.count()).select_from(OIDCAuthEvent).where(OIDCAuthEvent.created_at >= start, OIDCAuthEvent.status == "error")
    ).scalar_one()

    oidc_total_prev = db.execute(
        select(func.count()).select_from(OIDCAuthEvent).where(OIDCAuthEvent.created_at >= prev_start, OIDCAuthEvent.created_at < start)
    ).scalar_one()
    oidc_err_prev = db.execute(
        select(func.count()).select_from(OIDCAuthEvent).where(
            OIDCAuthEvent.created_at >= prev_start, OIDCAuthEvent.created_at < start, OIDCAuthEvent.status == "error"
        )
    ).scalar_one()

    auth_err_rate_now = (float(oidc_err_now) / float(oidc_total_now) * 100.0) if oidc_total_now else None
    auth_err_rate_prev = (float(oidc_err_prev) / float(oidc_total_prev) * 100.0) if oidc_total_prev else None

    # Offline host ratio.
    grace_s = int(getattr(settings, "agent_online_grace_seconds", 10) or 10)
    online_cutoff = now.timestamp() - grace_s
    total_hosts = int(db.execute(select(func.count()).select_from(Host)).scalar_one() or 0)
    online_hosts = int(
        db.execute(
            select(func.count())
            .select_from(Host)
            .where(Host.last_seen.is_not(None), func.extract("epoch", Host.last_seen) >= online_cutoff)
        ).scalar_one()
        or 0
    )
    offline_ratio_now = (float(max(0, total_hosts - online_hosts)) / float(total_hosts) * 100.0) if total_hosts else None

    return {
        "window_hours": hours,
        "ts": now.isoformat(),
        "kpis": {
            "job_success_rate": {
                "value": success_rate_now,
                "previous": success_rate_prev,
                "unit": "percent",
                "sample_count": int(comp_now or 0),
                "previous_sample_count": int(comp_prev or 0),
            },
            "median_patch_duration": {
                "value": median_patch_now,
                "previous": median_patch_prev,
                "unit": "seconds",
                "sample_count": len(patch_now_durations),
                "previous_sample_count": len(patch_prev_durations),
            },
            "auth_error_rate": {
                "value": auth_err_rate_now,
                "previous": auth_err_rate_prev,
                "unit": "percent",
                "sample_count": int(oidc_total_now or 0),
                "previous_sample_count": int(oidc_total_prev or 0),
            },
            "offline_host_ratio": {
                "value": offline_ratio_now,
                "previous": None,
                "unit": "percent",
                "sample_count": int(total_hosts or 0),
                "previous_sample_count": None,
            },
        },
    }


@router.get("/slo.csv")
def dashboard_slo_csv(
    hours: int = Query(24 * 7, ge=1, le=24 * 90),
    bucket_hours: int = Query(24, ge=1, le=24 * 7),
    db: Session = Depends(get_db),
    user=Depends(require_ui_user),
):
    now = datetime.now(timezone.utc)
    start = now - timedelta(hours=hours)

    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow([
        "window_start",
        "window_end",
        "job_success_rate_pct",
        "job_success_rate_samples",
        "median_patch_duration_s",
        "median_patch_duration_samples",
        "auth_error_rate_pct",
        "auth_error_rate_samples",
        "offline_host_ratio_pct",
        "offline_host_ratio_samples",
    ])

    cur = start
    while cur < now:
        end = min(cur + timedelta(hours=bucket_hours), now)
        m = _slo_window_metrics(db, start=cur, end=end, now_for_offline=end)
        writer.writerow([
            cur.isoformat(),
            end.isoformat(),
            m["job_success_rate"]["value"],
            m["job_success_rate"]["sample_count"],
            m["median_patch_duration"]["value"],
            m["median_patch_duration"]["sample_count"],
            m["auth_error_rate"]["value"],
            m["auth_error_rate"]["sample_count"],
            m["offline_host_ratio"]["value"],
            m["offline_host_ratio"]["sample_count"],
        ])
        cur = end

    return Response(
        content=out.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=slo_{hours}h_{bucket_hours}h.csv"},
    )


@router.get("/maintenance-window")
def dashboard_maintenance_window(user=Depends(require_ui_user)):
    start = str(getattr(settings, "maintenance_window_start_hhmm", "01:00") or "01:00")
    end = str(getattr(settings, "maintenance_window_end_hhmm", "05:00") or "05:00")
    tz = str(getattr(settings, "maintenance_window_timezone", "UTC") or "UTC")
    enabled = bool(getattr(settings, "maintenance_window_enabled", False))
    guarded = [x.strip() for x in str(getattr(settings, "maintenance_window_guarded_actions", "") or "").split(",") if x.strip()]

    return {
        "enabled": enabled,
        "timezone": tz,
        "start": start,
        "end": end,
        "guarded_actions": guarded,
        "within_window_now": bool(is_within_maintenance_window()),
    }


@router.get("/attention")
async def dashboard_attention(
    db: Session = Depends(get_db),
    user=Depends(require_ui_user),
    limit: int = Query(50, ge=1, le=500),
    include_live: bool = Query(True),
    force_live: bool = Query(False),
):
    """Return a list of hosts that need attention + why.

    Includes offline/reboot-required/security-updates from DB.
    Optionally also queries live metrics (disk / load) from agents.
    """

    now = datetime.now(timezone.utc)
    grace_s = int(getattr(settings, "agent_online_grace_seconds", 10) or 10)
    online_cutoff = now.timestamp() - grace_s

    hosts = [
        h for h in db.execute(select(Host).order_by(Host.hostname.asc()).limit(limit * 5)).scalars().all()
        if is_host_visible_to_user(db, user, h)
    ][:limit]

    # Per-host update counts
    upd_rows = db.execute(
        select(
            HostPackageUpdate.host_id,
            func.count().label("updates_total"),
            func.sum(cast(HostPackageUpdate.is_security, Integer)).label("security_total"),
        )
        .where(HostPackageUpdate.update_available == True)  # noqa: E712
        .group_by(HostPackageUpdate.host_id)
    ).all()
    upd_map = {str(r[0]): {"updates_total": int(r[1] or 0), "security_total": int(r[2] or 0)} for r in upd_rows}

    items: list[dict] = []
    online_agent_ids: list[str] = []

    for h in hosts:
        hid = str(h.id)
        last_seen_ts = h.last_seen.timestamp() if h.last_seen else None
        online = bool(last_seen_ts is not None and last_seen_ts >= online_cutoff)

        issues = []
        if not online:
            issues.append({"kind": "offline", "message": f"offline (grace {grace_s}s)"})
        if bool(getattr(h, "reboot_required", False)):
            issues.append({"kind": "reboot_required", "message": "reboot required"})

        u = upd_map.get(hid) or {"updates_total": 0, "security_total": 0}
        if u["security_total"] > 0:
            issues.append({"kind": "security_updates", "message": f"{u['security_total']} security updates"})
        elif u["updates_total"] > 0:
            issues.append({"kind": "updates", "message": f"{u['updates_total']} updates"})

        if online:
            online_agent_ids.append(h.agent_id)

        items.append(
            {
                "agent_id": h.agent_id,
                "hostname": h.hostname,
                "online": online,
                "last_seen": h.last_seen.isoformat() if h.last_seen else None,
                "issues": issues,
            }
        )

    # Use cached snapshots first (fresh within 5 minutes)
    try:
        cutoff = now - timedelta(minutes=5)
        subq = (
            select(HostMetricsSnapshot.agent_id, func.max(HostMetricsSnapshot.recorded_at).label("max_t"))
            .where(HostMetricsSnapshot.recorded_at >= cutoff)
            .group_by(HostMetricsSnapshot.agent_id)
            .subquery()
        )
        latest = db.execute(
            select(HostMetricsSnapshot)
            .join(subq, (HostMetricsSnapshot.agent_id == subq.c.agent_id) & (HostMetricsSnapshot.recorded_at == subq.c.max_t))
        ).scalars().all()
        snap_map = {s.agent_id: s for s in latest}

        for it in items:
            s = snap_map.get(it["agent_id"])
            if not s:
                continue
            # disk
            if s.disk_percent_used is not None:
                try:
                    d = float(s.disk_percent_used)
                    if d >= 90:
                        it["issues"].append({"kind": "disk", "message": f"disk {d:.0f}%"})
                except Exception:
                    pass
            # cpu
            if s.load_1min is not None and s.vcpus:
                try:
                    load1 = float(s.load_1min)
                    v = int(s.vcpus) if int(s.vcpus) > 0 else 1
                    ratio = load1 / float(v)
                    if ratio >= 1.5:
                        it["issues"].append({"kind": "cpu", "message": f"high load {load1:.2f} (/{v} vCPU)"})
                except Exception:
                    pass
    except Exception:
        # Cache is best-effort
        pass

    # Live metrics (disk % and cpu load ratio)
    # Only query hosts missing recent cached metrics.
    if include_live:
        # Limit live queries to avoid overload.
        cutoff = now - timedelta(minutes=5)
        recent = set(
            db.execute(select(HostMetricsSnapshot.agent_id).where(HostMetricsSnapshot.recorded_at >= cutoff)).scalars().all()
        )
        if force_live:
            recent = set()
        live_targets = [aid for aid in online_agent_ids if aid and aid not in recent][: min(len(online_agent_ids), 50)]
        if live_targets:
            with transaction(db):
                created = create_job_with_runs(db=db, job_type="query-metrics", payload={}, agent_ids=live_targets, commit=False)
            job_id = created.job.id

            await push_job_to_agents(
                agent_ids=live_targets,
                job_payload_builder=lambda aid: {"job_id": created.job_key, "type": "query-metrics"},
            )

            # Poll for up to ~15s for runs to finish (some hosts can be slow)
            import asyncio
            import json

            deadline = asyncio.get_running_loop().time() + 15.0
            pending = set(live_targets)
            run_map: dict[str, dict] = {}

            while pending and asyncio.get_running_loop().time() < deadline:
                rows = db.execute(select(JobRun).where(JobRun.job_id == job_id, JobRun.agent_id.in_(list(pending)))).scalars().all()
                for r in rows:
                    if r.status in ("success", "failed"):
                        pending.discard(r.agent_id)
                        run_map[r.agent_id] = {
                            "status": r.status,
                            "stdout": r.stdout,
                            "error": r.error,
                        }
                await asyncio.sleep(0.3)

            attempted = set(live_targets)

            # Merge into items (only for the hosts we attempted live queries on)
            for it in items:
                aid = it["agent_id"]
                if aid not in attempted:
                    continue
                rr = run_map.get(aid)
                if not rr:
                    it["issues"].append({"kind": "metrics", "message": "metrics pending/timeout"})
                    continue
                if rr.get("status") != "success":
                    it["issues"].append({"kind": "metrics", "message": f"metrics failed: {rr.get('error') or 'unknown'}"})
                    continue
                try:
                    payload = json.loads(rr.get("stdout") or "{}")
                except Exception:
                    payload = {}
                metrics = payload.get("metrics") if isinstance(payload, dict) else None
                if not isinstance(metrics, dict):
                    continue

                disk = metrics.get("disk_usage") if isinstance(metrics.get("disk_usage"), dict) else {}
                cpu = metrics.get("cpu") if isinstance(metrics.get("cpu"), dict) else {}

                disk_pct = disk.get("percent_used")
                if disk_pct is not None:
                    try:
                        disk_pct_f = float(disk_pct)
                        if disk_pct_f >= 90:
                            it["issues"].append({"kind": "disk", "message": f"disk {disk_pct_f:.0f}%"})
                    except Exception:
                        pass

                load1 = cpu.get("load_1min")
                vcpus = cpu.get("vcpus")
                try:
                    load1_f = float(load1)
                    vcpus_i = int(vcpus) if int(vcpus) > 0 else 1
                    ratio = load1_f / float(vcpus_i)
                    if ratio >= 1.5:
                        it["issues"].append({"kind": "cpu", "message": f"high load {load1_f:.2f} (/{vcpus_i} vCPU)"})
                except Exception:
                    pass

    # Only return hosts that have issues
    items = [x for x in items if x.get("issues")]

    # Sort by severity: offline > disk/cpu > security > reboot > other
    priority = {"offline": 0, "disk": 1, "cpu": 1, "security_updates": 2, "reboot_required": 3, "updates": 4}

    def item_key(it: dict):
        kinds = [i.get("kind") for i in (it.get("issues") or [])]
        best = min([priority.get(k, 9) for k in kinds] or [9])
        return (best, it.get("hostname") or it.get("agent_id") or "")

    items.sort(key=item_key)
    return {"ts": now.isoformat(), "count": len(items), "items": items}


@router.get("/failed-runs")
def list_failed_runs(
    db: Session = Depends(get_db),
    user=Depends(require_ui_user),
    hours: int = Query(24, ge=1, le=168),
    limit: int = Query(50, ge=1, le=500),
):
    """List failed job runs within the past N hours (default 24h)."""

    now = datetime.now(timezone.utc)
    since = now - timedelta(hours=hours)

    rows = db.execute(
        select(JobRun, Job)
        .join(Job, Job.id == JobRun.job_id)
        .where(
            JobRun.status == "failed",
            JobRun.finished_at.is_not(None),
            JobRun.finished_at >= since,
        )
        .order_by(JobRun.finished_at.desc())
        .limit(limit)
    ).all()

    items = []
    for jr, job in rows:
        items.append(
            {
                "job_key": job.job_key,
                "job_type": job.job_type,
                "agent_id": jr.agent_id,
                "finished_at": jr.finished_at.isoformat() if jr.finished_at else None,
                "exit_code": jr.exit_code,
                "error": jr.error,
                "stderr": (jr.stderr or "")[-4000:],
                "stdout": (jr.stdout or "")[-4000:],
            }
        )

    return {"hours": hours, "limit": limit, "count": len(items), "items": items}


@router.post("/alerts/teams/test")
def dashboard_teams_test_alert(db: Session = Depends(get_db), user=Depends(require_admin_user)):
    if not bool(getattr(settings, "teams_alerts_enabled", False)):
        raise HTTPException(400, "Teams alerts are disabled (set TEAMS_ALERTS_ENABLED=true)")
    webhook = (getattr(settings, "teams_webhook_url", None) or "").strip()
    if not webhook:
        raise HTTPException(400, "TEAMS_WEBHOOK_URL is not configured")

    post_teams_message(
        webhook,
        title="Fleet Teams integration test",
        lines=[
            f"Triggered by: {getattr(user, 'username', 'unknown')}",
            "If you can read this, Teams webhook is configured correctly.",
        ],
    )
    return {"ok": True}


@router.get("/notifications")
def dashboard_notifications(db: Session = Depends(get_db), user=Depends(require_ui_user), limit: int = Query(30, ge=1, le=200)):
    now = datetime.now(timezone.utc)
    grace_s = int(getattr(settings, "agent_online_grace_seconds", 10) or 10)
    online_cutoff = now.timestamp() - grace_s

    dedupe_enabled = bool(getattr(settings, "notifications_dedupe_enabled", True))
    cooldown_s = int(getattr(settings, "notifications_dedupe_cooldown_seconds", 1800) or 1800)
    if cooldown_s < 0:
        cooldown_s = 0

    candidates: list[dict] = []

    allowed_agent_ids = {
        h.agent_id for h in db.execute(select(Host)).scalars().all() if is_host_visible_to_user(db, user, h)
    }

    # Offline hosts (top priority)
    hosts = db.execute(select(Host).order_by(Host.last_seen.asc().nullsfirst()).limit(200)).scalars().all()
    for h in hosts:
        if h.agent_id not in allowed_agent_ids:
            continue
        last_seen_ts = h.last_seen.timestamp() if h.last_seen else None
        online = bool(last_seen_ts is not None and last_seen_ts >= online_cutoff)
        if not online:
            last_seen = h.last_seen.isoformat() if h.last_seen else None
            nid = f"offline:{h.agent_id}:{last_seen or 'never'}"
            candidates.append({
                "id": nid,
                "dedupe_key": f"offline:{h.agent_id}",
                "severity": "high",
                "kind": "offline",
                "title": f"Host offline: {h.hostname or h.agent_id}",
                "detail": f"Last seen: {last_seen or 'never'}",
                "ts": last_seen or now.isoformat(),
            })

    # Failed job runs (24h)
    failed_rows = db.execute(
        select(JobRun, Job)
        .join(Job, Job.id == JobRun.job_id)
        .where(JobRun.status == "failed", JobRun.finished_at.is_not(None), JobRun.finished_at >= (now - timedelta(hours=24)))
        .order_by(JobRun.finished_at.desc())
        .limit(50)
    ).all()
    for jr, job in failed_rows:
        if (jr.agent_id or "") not in allowed_agent_ids:
            continue
        ts = jr.finished_at.isoformat() if jr.finished_at else now.isoformat()
        nid = f"failed:{job.job_key}:{jr.agent_id}:{ts}"
        candidates.append({
            "id": nid,
            "dedupe_key": f"failed_run:{jr.agent_id}:{job.job_type}",
            "severity": "high",
            "kind": "failed_run",
            "title": f"Failed run on {jr.agent_id}",
            "detail": f"{job.job_type} ({job.job_key}) exit={jr.exit_code if jr.exit_code is not None else 'n/a'}",
            "ts": ts,
        })

    # Security backlog by host (>=10)
    sec_rows = db.execute(
        select(Host.agent_id, Host.hostname, func.count().label("sec_count"))
        .join(HostPackageUpdate, HostPackageUpdate.host_id == Host.id)
        .where(HostPackageUpdate.update_available == True, HostPackageUpdate.is_security == True)  # noqa: E712
        .group_by(Host.agent_id, Host.hostname)
        .having(func.count() >= 10)
        .order_by(func.count().desc())
        .limit(50)
    ).all()
    for agent_id, hostname, sec_count in sec_rows:
        if (agent_id or "") not in allowed_agent_ids:
            continue
        nid = f"sec-backlog:{agent_id}:{int(sec_count or 0)}"
        candidates.append({
            "id": nid,
            "dedupe_key": f"security_backlog:{agent_id}",
            "severity": "medium",
            "kind": "security_backlog",
            "title": f"Security backlog: {hostname or agent_id}",
            "detail": f"{int(sec_count or 0)} security updates pending",
            "ts": now.isoformat(),
        })

    candidates.sort(key=lambda x: (x.get("severity") != "high", x.get("ts") or ""), reverse=True)

    suppressed = 0
    if dedupe_enabled and cooldown_s > 0 and candidates:
        keys = [str(x.get("dedupe_key") or "") for x in candidates if x.get("dedupe_key")]
        state_rows = db.execute(select(NotificationDedupeState).where(NotificationDedupeState.dedupe_key.in_(keys))).scalars().all()
        state_map = {str(r.dedupe_key): r for r in state_rows}

        allowed: list[dict] = []
        cooldown_cutoff = now - timedelta(seconds=cooldown_s)
        for it in candidates:
            key = str(it.get("dedupe_key") or "")
            if not key:
                allowed.append(it)
                continue
            st = state_map.get(key)
            if st and st.last_emitted_at:
                last_emitted = st.last_emitted_at
                if getattr(last_emitted, "tzinfo", None) is None:
                    last_emitted = last_emitted.replace(tzinfo=timezone.utc)
                if last_emitted > cooldown_cutoff:
                    suppressed += 1
                    continue
            allowed.append(it)

        items = allowed[:limit]

        if items:
            with transaction(db):
                for it in items:
                    key = str(it.get("dedupe_key") or "")
                    if not key:
                        continue
                    st = state_map.get(key)
                    if st:
                        st.last_emitted_at = now
                        st.last_title = str(it.get("title") or "")
                        st.kind = str(it.get("kind") or "")
                        st.severity = str(it.get("severity") or "")
                    else:
                        db.add(
                            NotificationDedupeState(
                                dedupe_key=key,
                                kind=str(it.get("kind") or ""),
                                severity=str(it.get("severity") or ""),
                                last_emitted_at=now,
                                last_title=str(it.get("title") or ""),
                            )
                        )

        for it in items:
            it.pop("dedupe_key", None)

        return {
            "count": len(items),
            "items": items,
            "ts": now.isoformat(),
            "suppressed": suppressed,
            "dedupe": {"enabled": True, "cooldown_seconds": cooldown_s},
        }

    items = candidates[:limit]
    for it in items:
        it.pop("dedupe_key", None)
    return {
        "count": len(items),
        "items": items,
        "ts": now.isoformat(),
        "suppressed": 0,
        "dedupe": {"enabled": bool(dedupe_enabled and cooldown_s > 0), "cooldown_seconds": cooldown_s},
    }


@router.get("/notifications/dedupe-state")
def dashboard_notifications_dedupe_state(
    db: Session = Depends(get_db),
    user=Depends(require_admin_user),
    limit: int = Query(100, ge=1, le=500),
    kind: str | None = Query(None),
    minutes: int = Query(1440, ge=1, le=10080),
):
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=minutes)
    q = select(NotificationDedupeState).where(NotificationDedupeState.last_emitted_at >= cutoff)
    if kind:
        q = q.where(NotificationDedupeState.kind == kind)

    rows = db.execute(q.order_by(NotificationDedupeState.last_emitted_at.desc()).limit(limit)).scalars().all()
    return {
        "count": len(rows),
        "limit": limit,
        "minutes": minutes,
        "items": [
            {
                "dedupe_key": r.dedupe_key,
                "kind": r.kind,
                "severity": r.severity,
                "last_emitted_at": r.last_emitted_at.isoformat() if r.last_emitted_at else None,
                "last_title": r.last_title,
            }
            for r in rows
        ],
    }


@router.post("/alerts/teams/morning-brief")
def dashboard_teams_morning_brief(db: Session = Depends(get_db), user=Depends(require_admin_user)):
    if not bool(getattr(settings, "teams_alerts_enabled", False)):
        raise HTTPException(400, "Teams alerts are disabled (set TEAMS_ALERTS_ENABLED=true)")
    webhook = (getattr(settings, "teams_webhook_url", None) or "").strip()
    if not webhook:
        raise HTTPException(400, "TEAMS_WEBHOOK_URL is not configured")

    now = datetime.now(timezone.utc)
    grace_s = int(getattr(settings, "agent_online_grace_seconds", 10) or 10)
    online_cutoff = now.timestamp() - grace_s

    total_hosts = int(db.execute(select(func.count()).select_from(Host)).scalar_one() or 0)
    online_hosts = int(
        db.execute(
            select(func.count())
            .select_from(Host)
            .where(Host.last_seen.is_not(None), func.extract("epoch", Host.last_seen) >= online_cutoff)
        ).scalar_one()
        or 0
    )
    offline_hosts = max(0, total_hosts - online_hosts)

    sec_total = int(
        db.execute(
            select(func.count())
            .select_from(HostPackageUpdate)
            .where(HostPackageUpdate.update_available == True, HostPackageUpdate.is_security == True)  # noqa: E712
        ).scalar_one()
        or 0
    )
    sec_hosts = int(
        db.execute(
            select(func.count(func.distinct(HostPackageUpdate.host_id)))
            .select_from(HostPackageUpdate)
            .where(HostPackageUpdate.update_available == True, HostPackageUpdate.is_security == True)  # noqa: E712
        ).scalar_one()
        or 0
    )

    reboot_required_hosts = int(
        db.execute(select(func.count()).select_from(Host).where(Host.reboot_required == True)).scalar_one() or 0  # noqa: E712
    )

    failed_runs_24h = int(
        db.execute(
            select(func.count())
            .select_from(JobRun)
            .where(JobRun.status == "failed", JobRun.finished_at.is_not(None), JobRun.finished_at >= (now - timedelta(hours=24)))
        ).scalar_one()
        or 0
    )

    post_teams_message(
        webhook,
        title="Fleet Morning Brief",
        lines=[
            f"Hosts online: {online_hosts}/{total_hosts} (offline: {offline_hosts})",
            f"Security updates: {sec_total} packages on {sec_hosts} hosts",
            f"Reboot required: {reboot_required_hosts} hosts",
            f"Failed runs (24h): {failed_runs_24h}",
            f"Triggered by: {getattr(user, 'username', 'unknown')}",
        ],
    )
    return {"ok": True}
