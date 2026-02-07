from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Query
from sqlalchemy import Integer, cast, func, select
from sqlalchemy.orm import Session

from ..config import settings
from ..db import get_db
from ..deps import require_ui_user
from ..models import Host, HostMetricsSnapshot, HostPackageUpdate, Job, JobRun
from ..services.db_utils import transaction
from ..services.jobs import create_job_with_runs, push_job_to_agents

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

    hosts = db.execute(select(Host).order_by(Host.hostname.asc()).limit(limit)).scalars().all()

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
