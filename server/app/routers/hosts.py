from __future__ import annotations

from datetime import datetime, timezone, timedelta

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import and_, delete, func, or_, select
from sqlalchemy.orm import Session

from ..db import get_db
from ..deps import require_ui_user
from ..config import settings
from ..models import Host, HostMetricsSnapshot, HostPackage, HostPackageUpdate, HostLoadMetric
from ..models import HostCVEStatus, HostUser, PatchCampaign, PatchCampaignHost, Job, JobRun, CVEPackage, CronJob
from ..services.db_utils import transaction
from ..services.jobs import create_job_with_runs, push_job_to_agents
from ..services.hosts import is_host_online, seconds_since_seen
from ..services.job_wait import wait_for_job_run
from ..services.audit import log_event
from ..services.rbac import permissions_for
from ..services.user_scopes import is_host_visible_to_user
from ..services.host_router_utils import (
    apply_host_metadata_update,
    clean_optional_str,
    get_visible_host_or_404,
    normalize_env_map,
    require_host_control_permission,
    require_permission,
)
from ..services.package_names import sanitize_package_list
from ..services.deb_version import is_vulnerable
from ..schemas import HostMetadataUpdate

router = APIRouter(prefix="/hosts", tags=["hosts"])


@router.get("")
def list_hosts(online_only: bool = False, db: Session = Depends(get_db), user=Depends(require_ui_user)):
    rows = db.execute(select(Host).order_by(Host.hostname)).scalars().all()
    now = datetime.now(timezone.utc)
    return [
        {
            "agent_id": h.agent_id,
            "hostname": h.hostname,
            "fqdn": h.fqdn,
            "ip_address": getattr(h, "ip_address", None),
            "os_id": h.os_id,
            "os_version": h.os_version,
            "kernel": h.kernel,
            "labels": h.labels,
            "last_seen": h.last_seen,
            "reboot_required": bool(getattr(h, "reboot_required", False)),
            "is_online": is_host_online(h, now),
        }
        for h in rows
        if is_host_visible_to_user(db, user, h)
        if (not online_only or is_host_online(h, now))
    ]


@router.patch("/{agent_id}/metadata")
def update_host_metadata(
    agent_id: str,
    payload: HostMetadataUpdate,
    db: Session = Depends(get_db),
    user=Depends(require_ui_user),
):
    host = get_visible_host_or_404(db, user, agent_id)
    require_host_control_permission(user, host, "can_manage_users", "Admin privileges required")

    next_hostname = clean_optional_str(payload.hostname, field="hostname")
    next_role = clean_optional_str(payload.role, field="role")
    next_owner = clean_optional_str(payload.owner, field="owner")

    next_env = normalize_env_map(payload.env)

    labels = apply_host_metadata_update(host, hostname=next_hostname, role=next_role, owner=next_owner, env=next_env)
    db.commit()

    return {
        "ok": True,
        "host": {
            "agent_id": host.agent_id,
            "hostname": host.hostname,
            "labels": host.labels or {},
        },
    }


@router.post("/{agent_id}/reboot")
async def reboot_host(
    agent_id: str,
    db: Session = Depends(get_db),
    user=Depends(require_ui_user),
):
    host = get_visible_host_or_404(db, user, agent_id)
    require_host_control_permission(user, host, "can_manage_packages", "Insufficient permissions to reboot hosts")

    if not is_host_online(host):
        t = seconds_since_seen(host)
        if t is not None:
            raise HTTPException(503, f"Agent appears offline (last seen {int(t)}s ago)")
        raise HTTPException(503, "Agent appears offline")

    with transaction(db):
        created = create_job_with_runs(
            db=db,
            job_type="reboot",
            payload={},
            agent_ids=[agent_id],
            commit=False,
        )

    await push_job_to_agents(
        agent_ids=[agent_id],
        job_payload_builder=lambda aid: {"job_id": created.job_key, "type": "reboot"},
    )

    # Queue a delayed post-reboot refresh so reboot_required and pending updates are re-collected.
    refresh_run_at = datetime.now(timezone.utc) + timedelta(minutes=3)
    with transaction(db):
        refresh_cron = CronJob(
            user_id=getattr(user, "id"),
            name=f"post-reboot refresh {agent_id}",
            run_at=refresh_run_at,
            action="inventory-now",
            payload={"schedule": {"kind": "once", "timezone": "UTC"}},
            selector={"agent_ids": [agent_id]},
            status="scheduled",
        )
        db.add(refresh_cron)
        db.flush()

    try:
        log_event(
            db,
            action="hosts.reboot",
            actor=getattr(user, "username", None),
            target_type="host",
            target_name=agent_id,
            meta={
                "job_id": created.job_key,
                "refresh_cron_id": str(getattr(refresh_cron, "id", "")),
                "refresh_run_at": refresh_run_at.isoformat(),
            },
        )
    except Exception:
        pass

    return {
        "job_id": created.job_key,
        "agent_id": agent_id,
        "status": "queued",
        "refresh": {
            "cron_id": str(getattr(refresh_cron, "id", "")),
            "run_at": refresh_run_at,
            "action": "inventory-now",
        },
    }


@router.post("/cleanup-offline")
def cleanup_offline_hosts(
    older_than_minutes: int = 60,
    include_local: bool = False,
    dry_run: bool = False,
    db: Session = Depends(get_db),
    user=Depends(require_ui_user),
):
    """Delete hosts that have not been seen recently.

    This is meant as an admin/ops cleanup tool for labs where hosts are
    ephemeral and won't come back.

    Parameters:
      - older_than_minutes: hosts with last_seen < now - older_than_minutes are removed
      - include_local: whether to allow deleting the local dev agent (srv-001)
      - dry_run: if true, only report what would be deleted
    """

    perms = permissions_for(user)
    if (perms.get("role") or "operator") != "admin":
        raise HTTPException(403, "Admin privileges required")

    if older_than_minutes < 1:
        raise HTTPException(400, "older_than_minutes must be >= 1")
    if older_than_minutes > 60 * 24 * 30:
        raise HTTPException(400, "older_than_minutes too large")

    cutoff = datetime.now(timezone.utc) - timedelta(minutes=older_than_minutes)

    q = select(Host).where(Host.last_seen < cutoff)
    if not include_local:
        q = q.where(Host.agent_id != "srv-001")

    doomed_hosts = db.execute(q).scalars().all()
    doomed_agent_ids = [h.agent_id for h in doomed_hosts]
    doomed_host_ids = [h.id for h in doomed_hosts]

    if dry_run:
        return {
            "cutoff": cutoff.isoformat(),
            "older_than_minutes": older_than_minutes,
            "count": len(doomed_agent_ids),
            "agent_ids": doomed_agent_ids,
        }

    if not doomed_agent_ids:
        return {
            "cutoff": cutoff.isoformat(),
            "older_than_minutes": older_than_minutes,
            "deleted": [],
            "counts": {},
        }

    counts: dict[str, int] = {}

    with transaction(db):
        counts["host_packages"] = db.execute(delete(HostPackage).where(HostPackage.host_id.in_(doomed_host_ids))).rowcount or 0
        counts["host_package_updates"] = (
            db.execute(delete(HostPackageUpdate).where(HostPackageUpdate.host_id.in_(doomed_host_ids))).rowcount or 0
        )
        counts["host_cve_status"] = (
            db.execute(delete(HostCVEStatus).where(HostCVEStatus.host_id.in_(doomed_host_ids))).rowcount or 0
        )
        counts["host_users"] = db.execute(delete(HostUser).where(HostUser.host_id.in_(doomed_host_ids))).rowcount or 0

        # Patch campaign host rows keyed by agent_id
        counts["patch_campaign_hosts"] = (
            db.execute(delete(PatchCampaignHost).where(PatchCampaignHost.agent_id.in_(doomed_agent_ids))).rowcount or 0
        )

        # Metrics keyed by agent_id
        counts["host_load_metrics"] = (
            db.execute(delete(HostLoadMetric).where(HostLoadMetric.agent_id.in_(doomed_agent_ids))).rowcount or 0
        )
        counts["host_metrics_snapshots"] = (
            db.execute(delete(HostMetricsSnapshot).where(HostMetricsSnapshot.agent_id.in_(doomed_agent_ids))).rowcount
            or 0
        )

        counts["hosts"] = db.execute(delete(Host).where(Host.id.in_(doomed_host_ids))).rowcount or 0

    return {
        "cutoff": cutoff.isoformat(),
        "older_than_minutes": older_than_minutes,
        "deleted": doomed_agent_ids,
        "counts": counts,
    }


@router.post("/remove")
async def remove_hosts(
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(require_ui_user),
):
    """Remove specific hosts from inventory by agent_id.

    Body (JSON):
      - agent_ids: list[str] (required)
      - include_local: bool (optional, default false)
      - dry_run: bool (optional, default false)
    """

    perms = permissions_for(user)
    if (perms.get("role") or "operator") != "admin":
        raise HTTPException(403, "Admin privileges required")

    try:
        payload = await request.json()
    except Exception:
        payload = {}

    if not isinstance(payload, dict):
        raise HTTPException(400, "Invalid JSON body")

    raw_ids = payload.get("agent_ids")
    if not isinstance(raw_ids, list):
        raise HTTPException(400, "agent_ids must be a JSON list")

    include_local = bool(payload.get("include_local", False))
    dry_run = bool(payload.get("dry_run", False))

    seen: set[str] = set()
    agent_ids: list[str] = []
    for x in raw_ids:
        s = str(x or "").strip()
        if not s or s in seen:
            continue
        seen.add(s)
        agent_ids.append(s)

    if not agent_ids:
        raise HTTPException(400, "No valid agent_ids provided")
    if len(agent_ids) > 500:
        raise HTTPException(400, "Too many agent_ids (max 500)")

    blocked_local_agent_ids: list[str] = []
    if not include_local and "srv-001" in agent_ids:
        blocked_local_agent_ids.append("srv-001")

    q = select(Host).where(Host.agent_id.in_(agent_ids))
    if not include_local:
        q = q.where(Host.agent_id != "srv-001")

    doomed_hosts = db.execute(q).scalars().all()
    doomed_agent_ids = [h.agent_id for h in doomed_hosts]
    doomed_host_ids = [h.id for h in doomed_hosts]
    missing_agent_ids = [aid for aid in agent_ids if aid not in set(doomed_agent_ids) and aid not in set(blocked_local_agent_ids)]

    if dry_run:
        return {
            "requested": agent_ids,
            "found_agent_ids": doomed_agent_ids,
            "missing_agent_ids": missing_agent_ids,
            "blocked_local_agent_ids": blocked_local_agent_ids,
            "count": len(doomed_agent_ids),
        }

    if not doomed_agent_ids:
        return {
            "requested": agent_ids,
            "deleted": [],
            "missing_agent_ids": missing_agent_ids,
            "blocked_local_agent_ids": blocked_local_agent_ids,
            "counts": {},
        }

    counts: dict[str, int] = {}

    with transaction(db):
        counts["host_packages"] = db.execute(delete(HostPackage).where(HostPackage.host_id.in_(doomed_host_ids))).rowcount or 0
        counts["host_package_updates"] = (
            db.execute(delete(HostPackageUpdate).where(HostPackageUpdate.host_id.in_(doomed_host_ids))).rowcount or 0
        )
        counts["host_cve_status"] = (
            db.execute(delete(HostCVEStatus).where(HostCVEStatus.host_id.in_(doomed_host_ids))).rowcount or 0
        )
        counts["host_users"] = db.execute(delete(HostUser).where(HostUser.host_id.in_(doomed_host_ids))).rowcount or 0

        counts["patch_campaign_hosts"] = (
            db.execute(delete(PatchCampaignHost).where(PatchCampaignHost.agent_id.in_(doomed_agent_ids))).rowcount or 0
        )

        counts["host_load_metrics"] = (
            db.execute(delete(HostLoadMetric).where(HostLoadMetric.agent_id.in_(doomed_agent_ids))).rowcount or 0
        )
        counts["host_metrics_snapshots"] = (
            db.execute(delete(HostMetricsSnapshot).where(HostMetricsSnapshot.agent_id.in_(doomed_agent_ids))).rowcount
            or 0
        )

        counts["hosts"] = db.execute(delete(Host).where(Host.id.in_(doomed_host_ids))).rowcount or 0

    return {
        "requested": agent_ids,
        "deleted": doomed_agent_ids,
        "missing_agent_ids": missing_agent_ids,
        "blocked_local_agent_ids": blocked_local_agent_ids,
        "counts": counts,
    }


