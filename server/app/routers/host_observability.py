from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from ..config import settings
from ..db import get_db
from ..deps import require_ui_user
from ..models import HostLoadMetric, HostMetricsSnapshot, HostPackage, HostPackageUpdate, Job, JobRun, PatchCampaign, PatchCampaignHost
from ..services.db_utils import transaction
from ..services.host_router_utils import get_visible_host_or_404
from ..services.hosts import is_host_online, seconds_since_seen
from ..services.host_job_dispatch import (
    dispatch_host_job,
    parse_json_run_stdout,
    push_dispatched_host_job,
    require_successful_run,
    wait_for_host_job_or_504,
)

router = APIRouter(prefix="/hosts", tags=["hosts"])


@router.get("/{agent_id}/timeline")
def host_timeline(
    agent_id: str,
    limit: int = 30,
    db: Session = Depends(get_db),
    user=Depends(require_ui_user),
):
    if limit < 1:
        limit = 1
    if limit > 200:
        limit = 200

    get_visible_host_or_404(db, user, agent_id)

    rows = db.execute(
        select(JobRun, Job)
        .join(Job, JobRun.job_id == Job.id)
        .where(JobRun.agent_id == agent_id)
        .order_by(JobRun.finished_at.desc().nullslast(), JobRun.started_at.desc().nullslast(), Job.created_at.desc())
        .limit(limit)
    ).all()

    items = []
    for run, job in rows:
        ts = run.finished_at or run.started_at or job.created_at
        payload = job.payload if isinstance(job.payload, dict) else {}
        items.append({
            "time": ts,
            "job_id": job.job_key,
            "job_type": job.job_type,
            "status": run.status,
            "exit_code": run.exit_code,
            "started_at": run.started_at,
            "finished_at": run.finished_at,
            "created_by": job.created_by,
            "payload_username": payload.get("username"),
            "payload_sudo_profile": payload.get("sudo_profile"),
            "logs_zip": f"/jobs/{job.job_key}/logs.zip",
            "stdout": f"/jobs/{job.job_key}/runs/{agent_id}/stdout.txt",
            "stderr": f"/jobs/{job.job_key}/runs/{agent_id}/stderr.txt",
        })

    return {"agent_id": agent_id, "items": items}


@router.get("/{agent_id}/drift")
def host_drift(
    agent_id: str,
    db: Session = Depends(get_db),
    user=Depends(require_ui_user),
):
    host = get_visible_host_or_404(db, user, agent_id)

    now = datetime.now(timezone.utc)
    online = is_host_online(host, now)

    latest_inventory_at = db.execute(
        select(func.max(HostPackage.collected_at)).where(HostPackage.host_id == host.id)
    ).scalar_one()
    inv_age_h = None
    if latest_inventory_at:
        inv_age_h = max(0.0, (now - latest_inventory_at).total_seconds() / 3600.0)

    sec_updates = db.execute(
        select(func.count())
        .select_from(HostPackageUpdate)
        .where(
            HostPackageUpdate.host_id == host.id,
            HostPackageUpdate.update_available == True,  # noqa: E712
            HostPackageUpdate.is_security == True,  # noqa: E712
        )
    ).scalar_one()
    all_updates = db.execute(
        select(func.count())
        .select_from(HostPackageUpdate)
        .where(
            HostPackageUpdate.host_id == host.id,
            HostPackageUpdate.update_available == True,  # noqa: E712
        )
    ).scalar_one()

    last_success_inventory_at = db.execute(
        select(func.max(JobRun.finished_at))
        .select_from(JobRun)
        .join(Job, JobRun.job_id == Job.id)
        .where(
            JobRun.agent_id == agent_id,
            Job.job_type == "inventory-now",
            JobRun.status == "success",
        )
    ).scalar_one()

    latest_security_campaign_success_at = db.execute(
        select(func.max(PatchCampaignHost.finished_at))
        .select_from(PatchCampaignHost)
        .join(PatchCampaign, PatchCampaignHost.campaign_id == PatchCampaign.id)
        .where(
            PatchCampaignHost.agent_id == agent_id,
            PatchCampaign.kind == "security-updates",
            PatchCampaignHost.status == "success",
        )
    ).scalar_one()

    remediations = [
        ("inventory-now", last_success_inventory_at),
        ("security-campaign", latest_security_campaign_success_at),
    ]
    remediations = [(name, ts) for name, ts in remediations if ts is not None]
    last_remediated_at = None
    last_remediated_via = None
    if remediations:
        remediations.sort(key=lambda x: x[1], reverse=True)
        last_remediated_via, last_remediated_at = remediations[0]

    failed_runs_24h = db.execute(
        select(func.count())
        .select_from(JobRun)
        .join(Job, JobRun.job_id == Job.id)
        .where(
            JobRun.agent_id == agent_id,
            JobRun.status == "failed",
            JobRun.finished_at.is_not(None),
            JobRun.finished_at >= (now - timedelta(hours=24)),
        )
    ).scalar_one()

    labels = host.labels if isinstance(host.labels, dict) else {}
    required_labels = ["env", "role"]
    missing_labels = [k for k in required_labels if not str(labels.get(k) or "").strip()]

    sec_updates_n = int(sec_updates or 0)
    all_updates_n = int(all_updates or 0)
    failed_runs_n = int(failed_runs_24h or 0)

    checks = [
        {
            "key": "online",
            "title": "Host online",
            "status": "pass" if online else "warn",
            "severity": "ok" if online else "critical",
            "detail": "Host heartbeat is healthy" if online else "Host is offline/stale",
        },
        {
            "key": "inventory_freshness",
            "title": "Inventory freshness",
            "status": "pass" if (inv_age_h is not None and inv_age_h <= 24) else "warn",
            "severity": "ok" if (inv_age_h is not None and inv_age_h <= 24) else "warn",
            "detail": (
                f"Last package inventory {inv_age_h:.1f}h ago" if inv_age_h is not None else "No package inventory data"
            ),
        },
        {
            "key": "inventory_run_recent",
            "title": "Inventory job health",
            "status": "pass" if last_success_inventory_at and last_success_inventory_at >= (now - timedelta(hours=24)) else "warn",
            "severity": "ok" if last_success_inventory_at and last_success_inventory_at >= (now - timedelta(hours=24)) else "warn",
            "detail": (
                f"Last successful inventory job: {last_success_inventory_at.isoformat()}" if last_success_inventory_at else "No successful inventory-now job in history"
            ),
        },
        {
            "key": "security_updates",
            "title": "Security updates backlog",
            "status": "pass" if sec_updates_n == 0 else "warn",
            "severity": "ok" if sec_updates_n == 0 else ("critical" if sec_updates_n >= 20 else "warn"),
            "detail": f"{sec_updates_n} security package(s) pending",
        },
        {
            "key": "all_updates",
            "title": "Total updates backlog",
            "status": "pass" if all_updates_n <= 10 else "warn",
            "severity": "ok" if all_updates_n <= 10 else ("critical" if all_updates_n >= 100 else "warn"),
            "detail": f"{all_updates_n} package update(s) pending",
        },
        {
            "key": "failed_runs_24h",
            "title": "Failed runs (24h)",
            "status": "pass" if failed_runs_n == 0 else "warn",
            "severity": "ok" if failed_runs_n == 0 else ("critical" if failed_runs_n >= 3 else "warn"),
            "detail": f"{failed_runs_n} failed job run(s) in last 24h",
        },
        {
            "key": "labels_baseline",
            "title": "Baseline labels",
            "status": "pass" if not missing_labels else "warn",
            "severity": "ok" if not missing_labels else "warn",
            "detail": "All baseline labels set" if not missing_labels else ("Missing: " + ", ".join(missing_labels)),
        },
        {
            "key": "reboot_required",
            "title": "Reboot required",
            "status": "warn" if bool(host.reboot_required) else "pass",
            "severity": "warn" if bool(host.reboot_required) else "ok",
            "detail": "Reboot required by host" if bool(host.reboot_required) else "No reboot required",
        },
    ]

    pass_count = len([c for c in checks if c["status"] == "pass"])
    warn_count = len([c for c in checks if c["status"] == "warn"])

    return {
        "agent_id": agent_id,
        "summary": {
            "checks_total": len(checks),
            "checks_pass": pass_count,
            "checks_warn": warn_count,
            "security_updates": int(sec_updates or 0),
            "all_updates": int(all_updates or 0),
            "failed_runs_24h": int(failed_runs_24h or 0),
            "missing_labels": missing_labels,
            "last_remediated_at": last_remediated_at,
            "last_remediated_via": last_remediated_via,
        },
        "checks": checks,
    }


@router.get("/{agent_id}/df")
async def get_df(agent_id: str, wait: bool = True, db: Session = Depends(get_db), user=Depends(require_ui_user)):
    host = get_visible_host_or_404(db, user, agent_id)

    if not is_host_online(host):
        t = seconds_since_seen(host)
        msg = f"Agent appears offline (last seen {int(t)}s ago)" if t is not None else "Agent appears offline"
        return {
            "stdout": msg,
            "unavailable": True,
            "reason": "agent_offline",
            "last_seen_seconds_ago": int(t) if t is not None else None,
        }

    created, job_id, push_kwargs = dispatch_host_job(
        db=db,
        agent_id=agent_id,
        job_type="query-df",
        payload={},
    )

    await push_dispatched_host_job(push_kwargs=push_kwargs)

    if not wait:
        return {"job_id": created.job_key, "status": "queued", "message": "Job queued, poll /jobs/{job_id} for results"}

    timeout = 12
    run = await wait_for_host_job_or_504(
        job_id=job_id,
        agent_id=agent_id,
        timeout_s=timeout,
        timeout_message=f"Timeout waiting for df query after {timeout}s",
    )
    require_successful_run(run, error_message="df query failed", include_stdout=True)
    return {"stdout": run.stdout or ""}


@router.get("/{agent_id}/metrics")
async def get_metrics(agent_id: str, wait: bool = True, db: Session = Depends(get_db), user=Depends(require_ui_user)):
    host = get_visible_host_or_404(db, user, agent_id)

    if not is_host_online(host):
        t = seconds_since_seen(host)
        poll_grace = max(int(getattr(settings, "agent_online_grace_seconds", 30) or 30), 90)
        if t is None or t > poll_grace:
            snap = db.execute(
                select(HostMetricsSnapshot)
                .where(HostMetricsSnapshot.agent_id == agent_id)
                .order_by(HostMetricsSnapshot.recorded_at.desc())
                .limit(1)
            ).scalar_one_or_none()
            if snap:
                ip_list = []
                if getattr(host, "ip_address", None):
                    ip_list.append(host.ip_address)
                return {
                    "agent_id": agent_id,
                    "disk_usage": {
                        "percent_used": float(snap.disk_percent_used) if snap.disk_percent_used not in (None, "") else None,
                    },
                    "memory": {
                        "percent_used": float(snap.mem_percent_used) if snap.mem_percent_used not in (None, "") else None,
                    },
                    "cpu": {
                        "vcpus": snap.vcpus,
                        "load_1min": float(snap.load_1min) if snap.load_1min not in (None, "") else None,
                    },
                    "ip_addresses": ip_list,
                    "stale": True,
                    "reason": "agent_offline_snapshot",
                    "last_seen_seconds_ago": int(t) if t is not None else None,
                    "snapshot_recorded_at": snap.recorded_at,
                }
            return {
                "agent_id": agent_id,
                "disk_usage": {},
                "memory": {},
                "cpu": {},
                "ip_addresses": [],
                "unavailable": True,
                "reason": "agent_offline",
                "last_seen_seconds_ago": int(t) if t is not None else None,
            }

    created, job_id, push_kwargs = dispatch_host_job(
        db=db,
        agent_id=agent_id,
        job_type="query-metrics",
        payload={},
    )

    await push_dispatched_host_job(push_kwargs=push_kwargs)

    if not wait:
        return {"job_id": created.job_key, "status": "queued", "message": "Job queued, poll /jobs/{job_id} for results"}

    timeout = 12
    run = await wait_for_host_job_or_504(
        job_id=job_id,
        agent_id=agent_id,
        timeout_s=timeout,
        timeout_message=f"Timeout waiting for metrics query after {timeout}s",
    )
    require_successful_run(run, error_message="Metrics query failed")

    payload = parse_json_run_stdout(run, {})
    if isinstance(payload, dict) and isinstance(payload.get("metrics"), dict):
        metrics = payload["metrics"]
        try:
            cpu = metrics.get("cpu") if isinstance(metrics, dict) else None
            disk = metrics.get("disk_usage") if isinstance(metrics, dict) else None
            mem = metrics.get("memory") if isinstance(metrics, dict) else None

            snap = HostMetricsSnapshot(
                agent_id=agent_id,
                disk_percent_used=str(disk.get("percent_used")) if isinstance(disk, dict) and disk.get("percent_used") is not None else None,
                mem_percent_used=str(mem.get("percent_used")) if isinstance(mem, dict) and mem.get("percent_used") is not None else None,
                load_1min=str(cpu.get("load_1min")) if isinstance(cpu, dict) and cpu.get("load_1min") is not None else None,
                vcpus=int(cpu.get("vcpus")) if isinstance(cpu, dict) and cpu.get("vcpus") is not None else None,
            )
            db.add(snap)

            if isinstance(cpu, dict) and cpu.get("load_1min") is not None:
                db.add(
                    HostLoadMetric(
                        agent_id=agent_id,
                        load_1min=str(cpu.get("load_1min")),
                        load_5min=str(cpu.get("load_5min")),
                        load_15min=str(cpu.get("load_15min")),
                    )
                )

            db.commit()

            cutoff = datetime.now(timezone.utc) - timedelta(days=7)
            db.execute(
                delete(HostLoadMetric).where(
                    HostLoadMetric.agent_id == agent_id,
                    HostLoadMetric.recorded_at < cutoff,
                )
            )
            db.execute(
                delete(HostMetricsSnapshot).where(
                    HostMetricsSnapshot.agent_id == agent_id,
                    HostMetricsSnapshot.recorded_at < cutoff,
                )
            )
            db.commit()
        except Exception:
            db.rollback()
        return metrics
    return payload if isinstance(payload, dict) else {}


@router.get("/{agent_id}/load-history")
def get_load_history(
    agent_id: str,
    since_seconds: int = 3600,
    limit: int = 600,
    db: Session = Depends(get_db),
    user=Depends(require_ui_user),
):
    if since_seconds < 10:
        since_seconds = 10
    if since_seconds > 60 * 60 * 24 * 30:
        since_seconds = 60 * 60 * 24 * 30

    if limit < 1:
        limit = 1
    if limit > 5000:
        limit = 5000

    get_visible_host_or_404(db, user, agent_id)

    cutoff = datetime.now(timezone.utc) - timedelta(seconds=since_seconds)
    rows = (
        db.execute(
            select(HostLoadMetric)
            .where(HostLoadMetric.agent_id == agent_id, HostLoadMetric.recorded_at >= cutoff)
            .order_by(HostLoadMetric.recorded_at.asc())
            .limit(limit)
        )
        .scalars()
        .all()
    )

    history = []
    for r in rows:
        try:
            l1 = float(r.load_1min)
        except Exception:
            l1 = None
        try:
            l5 = float(r.load_5min)
        except Exception:
            l5 = None
        try:
            l15 = float(r.load_15min)
        except Exception:
            l15 = None

        history.append(
            {
                "time": r.recorded_at.isoformat() if r.recorded_at else None,
                "load_1min": l1,
                "load_5min": l5,
                "load_15min": l15,
            }
        )

    return {"agent_id": agent_id, "history": history}


@router.get("/{agent_id}/top-processes")
async def get_top_processes(agent_id: str, wait: bool = True, db: Session = Depends(get_db), user=Depends(require_ui_user)):
    host = get_visible_host_or_404(db, user, agent_id)

    if not is_host_online(host):
        t = seconds_since_seen(host)
        poll_grace = max(int(getattr(settings, "agent_online_grace_seconds", 30) or 30), 90)
        if t is None or t > poll_grace:
            return {
                "agent_id": agent_id,
                "top_processes": [],
                "unavailable": True,
                "reason": "agent_offline",
                "last_seen_seconds_ago": int(t) if t is not None else None,
            }

    created, job_id, push_kwargs = dispatch_host_job(
        db=db,
        agent_id=agent_id,
        job_type="query-top-processes",
        payload={},
    )

    await push_dispatched_host_job(push_kwargs=push_kwargs)

    if not wait:
        return {"job_id": created.job_key, "status": "queued", "message": "Job queued, poll /jobs/{job_id} for results"}

    timeout = 6
    run = await wait_for_host_job_or_504(
        job_id=job_id,
        agent_id=agent_id,
        timeout_s=timeout,
        timeout_message=f"Timeout waiting for top-processes after {timeout}s",
        poll_interval_s=0.2,
    )
    require_successful_run(run, error_message="Top processes query failed")

    payload = parse_json_run_stdout(run, {})
    if isinstance(payload, dict) and "top_processes" in payload:
        return payload
    return {"top_processes": []}
