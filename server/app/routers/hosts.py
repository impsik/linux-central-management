from __future__ import annotations

from datetime import datetime, timezone, timedelta

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import and_, delete, func, or_, select
from sqlalchemy.orm import Session

from ..db import get_db
from ..deps import require_ui_user
from ..models import Host, HostMetricsSnapshot, HostPackage, HostPackageUpdate, HostLoadMetric
from ..models import HostCVEStatus, HostUser, PatchCampaignHost
from ..services.db_utils import transaction
from ..services.jobs import create_job_with_runs, push_job_to_agents
from ..services.hosts import is_host_online, seconds_since_seen
from ..services.job_wait import wait_for_job_run
from ..services.audit import log_event
from ..services.rbac import permissions_for

router = APIRouter(prefix="/hosts", tags=["hosts"])


@router.get("")
def list_hosts(online_only: bool = False, db: Session = Depends(get_db)):
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
        if (not online_only or is_host_online(h, now))
    ]


@router.post("/cleanup-offline")
def cleanup_offline_hosts(
    older_than_minutes: int = 60,
    include_local: bool = False,
    dry_run: bool = False,
    db: Session = Depends(get_db),
    _user=Depends(require_ui_user),
):
    """Delete hosts that have not been seen recently.

    This is meant as an admin/ops cleanup tool for labs where hosts are
    ephemeral and won't come back.

    Parameters:
      - older_than_minutes: hosts with last_seen < now - older_than_minutes are removed
      - include_local: whether to allow deleting the local dev agent (srv-001)
      - dry_run: if true, only report what would be deleted
    """

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


@router.get("/{agent_id}/packages")
def list_host_packages(
    agent_id: str,
    search: str | None = None,
    upgradable_only: bool = False,
    limit: int = 500,
    offset: int = 0,
    db: Session = Depends(get_db),
):
    if limit < 1:
        limit = 1
    if limit > 2000:
        limit = 2000
    if offset < 0:
        offset = 0

    host = db.execute(select(Host).where(Host.agent_id == agent_id)).scalar_one_or_none()
    if not host:
        raise HTTPException(404, "Host not found")

    base_filter = [HostPackage.host_id == host.id]
    if search:
        q = f"%{search}%"
        base_filter.append(or_(HostPackage.name.ilike(q), HostPackage.version.ilike(q)))

    if upgradable_only:
        join_on = and_(HostPackageUpdate.host_id == HostPackage.host_id, HostPackageUpdate.name == HostPackage.name)
        total = db.execute(
            select(func.count())
            .select_from(HostPackage)
            .join(HostPackageUpdate, join_on)
            .where(
                *base_filter,
                HostPackageUpdate.update_available == True,  # noqa: E712
                HostPackageUpdate.candidate_version.is_not(None),
                HostPackageUpdate.candidate_version != HostPackage.version,
            )
        ).scalar_one()
    else:
        total = db.execute(select(func.count()).select_from(HostPackage).where(*base_filter)).scalar_one()

    collected_at = db.execute(select(func.max(HostPackage.collected_at)).where(*base_filter[:1])).scalar_one()

    if upgradable_only:
        join_on = and_(HostPackageUpdate.host_id == HostPackage.host_id, HostPackageUpdate.name == HostPackage.name)
        rows = db.execute(
            select(HostPackage)
            .join(HostPackageUpdate, join_on)
            .where(
                *base_filter,
                HostPackageUpdate.update_available == True,  # noqa: E712
                HostPackageUpdate.candidate_version.is_not(None),
                HostPackageUpdate.candidate_version != HostPackage.version,
            )
            .order_by(HostPackage.name.asc())
            .limit(limit)
            .offset(offset)
        ).scalars().all()
    else:
        rows = db.execute(
            select(HostPackage)
            .where(*base_filter)
            .order_by(HostPackage.name.asc())
            .limit(limit)
            .offset(offset)
        ).scalars().all()

    names = [r.name for r in rows]
    updates_map: dict[str, HostPackageUpdate] = {}
    last_checked_at = db.execute(
        select(func.max(HostPackageUpdate.checked_at)).where(HostPackageUpdate.host_id == host.id)
    ).scalar_one()
    if names:
        updates = db.execute(
            select(HostPackageUpdate).where(HostPackageUpdate.host_id == host.id, HostPackageUpdate.name.in_(names))
        ).scalars().all()
        updates_map = {u.name: u for u in updates}

    return {
        "agent_id": agent_id,
        "packages": [
            {
                "name": r.name,
                "version": r.version,
                "arch": r.arch,
                "update_available": bool(
                    updates_map.get(r.name)
                    and updates_map.get(r.name).update_available
                    and updates_map.get(r.name).candidate_version
                    and updates_map.get(r.name).candidate_version != r.version
                ),
                "candidate_version": updates_map.get(r.name).candidate_version if updates_map.get(r.name) else None,
            }
            for r in rows
        ],
        "total": int(total or 0),
        "limit": limit,
        "offset": offset,
        "collected_at": collected_at.isoformat() if collected_at else None,
        "updates_checked_at": last_checked_at.isoformat() if last_checked_at else None,
    }


@router.get("/{agent_id}/packages/{pkg_name}/info")
async def get_package_info(agent_id: str, pkg_name: str, wait: bool = True, db: Session = Depends(get_db)):
    host = db.execute(select(Host).where(Host.agent_id == agent_id)).scalar_one_or_none()
    if not host:
        raise HTTPException(404, "Host not found")

    if not is_host_online(host):
        t = seconds_since_seen(host)
        if t is not None:
            raise HTTPException(503, f"Agent appears offline (last seen {int(t)}s ago)")
        raise HTTPException(503, "Agent appears offline")

    pkg_name = (pkg_name or "").strip()
    if not pkg_name:
        raise HTTPException(400, "Package name is required")

    with transaction(db):
        created = create_job_with_runs(
            db=db,
            job_type="query-pkg-info",
            payload={"package_name": pkg_name},
            agent_ids=[agent_id],
            commit=False,
        )
    job_id = created.job.id

    await push_job_to_agents(
        agent_ids=[agent_id],
        job_payload_builder=lambda aid: {"job_id": created.job_key, "type": "query-pkg-info", "package_name": pkg_name},
    )

    if not wait:
        return {"job_id": created.job_key, "status": "queued"}

    timeout = 20
    res = await wait_for_job_run(job_id=job_id, agent_id=agent_id, timeout_s=timeout, poll_interval_s=0.3)
    if not res.run:
        raise HTTPException(504, f"Timeout waiting for package info after {timeout}s")

    run = res.run
    if run.status == "failed":
        msg = run.error or run.stderr or "Unknown error"
        raise HTTPException(500, f"Package info query failed: {msg}")

    from ..services.json_utils import loads_or

    return loads_or(run.stdout, {})


@router.post("/{agent_id}/packages/check-updates")
async def check_host_package_updates(agent_id: str, refresh: bool = True, wait: bool = True, db: Session = Depends(get_db)):
    host = db.execute(select(Host).where(Host.agent_id == agent_id)).scalar_one_or_none()
    if not host:
        raise HTTPException(404, "Host not found")

    with transaction(db):
        created = create_job_with_runs(
            db=db,
            job_type="query-pkg-updates",
            payload={"refresh": refresh},
            agent_ids=[agent_id],
            commit=False,
        )
    job_id = created.job.id

    await push_job_to_agents(
        agent_ids=[agent_id],
        job_payload_builder=lambda aid: {"job_id": created.job_key, "type": "query-pkg-updates", "refresh": refresh},
    )

    if not wait:
        return {"job_id": created.job_key, "status": "queued"}

    timeout = 35 if refresh else 15
    res = await wait_for_job_run(job_id=job_id, agent_id=agent_id, timeout_s=timeout, poll_interval_s=0.3)
    if not res.run:
        raise HTTPException(504, f"Timeout waiting for update check after {timeout}s")

    run = res.run
    if run.status == "failed":
        msg = run.error or run.stderr or "Unknown error"
        raise HTTPException(500, f"Update check failed: {msg}")

    import json

    payload = json.loads(run.stdout or "{}")
    checked_at_str = payload.get("checked_at")
    try:
        checked_at = (
            datetime.fromisoformat(checked_at_str.replace("Z", "+00:00")) if checked_at_str else datetime.now(timezone.utc)
        )
    except Exception:
        checked_at = datetime.now(timezone.utc)

    updates = payload.get("updates", []) or []

    db.execute(delete(HostPackageUpdate).where(HostPackageUpdate.host_id == host.id))
    for u in updates:
        name = (u.get("name") if isinstance(u, dict) else None) or ""
        name = str(name).strip()
        if not name:
            continue
        db.add(
            HostPackageUpdate(
                host_id=host.id,
                name=name,
                installed_version=(u.get("installed_version") if isinstance(u, dict) else None),
                candidate_version=(u.get("candidate_version") if isinstance(u, dict) else None),
                update_available=True,
                checked_at=checked_at,
            )
        )
    db.commit()

    return {"ok": True, "job_id": created.job_key, "updates": len(updates), "checked_at": checked_at.isoformat()}


@router.post("/{agent_id}/packages/refresh")
async def refresh_host_packages(agent_id: str, wait: bool = False, db: Session = Depends(get_db)):
    host = db.execute(select(Host).where(Host.agent_id == agent_id)).scalar_one_or_none()
    if not host:
        raise HTTPException(404, "Host not found")

    with transaction(db):
        created = create_job_with_runs(
            db=db,
            job_type="inventory-now",
            payload={},
            agent_ids=[agent_id],
            commit=False,
        )
    job_id = created.job.id

    await push_job_to_agents(
        agent_ids=[agent_id],
        job_payload_builder=lambda aid: {"job_id": created.job_key, "type": "inventory-now"},
    )

    if not wait:
        return {"job_id": created.job_key, "status": "queued"}

    timeout = 90
    res = await wait_for_job_run(job_id=job_id, agent_id=agent_id, timeout_s=timeout, poll_interval_s=0.3)
    if not res.run:
        raise HTTPException(504, f"Timeout waiting for inventory refresh after {timeout}s")

    run = res.run
    if run.status == "failed":
        msg = run.error or run.stderr or "Unknown error"
        raise HTTPException(500, f"Inventory refresh failed: {msg}")

    return {"job_id": created.job_key, "status": "success"}


@router.post("/{agent_id}/packages/action")
async def host_packages_action(
    agent_id: str,
    payload: dict,
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(require_ui_user),
):
    host = db.execute(select(Host).where(Host.agent_id == agent_id)).scalar_one_or_none()
    if not host:
        raise HTTPException(404, "Host not found")

    action = (payload.get("action") or "").strip()
    packages = payload.get("packages") or []
    if action not in ("upgrade", "reinstall", "remove"):
        raise HTTPException(400, "Invalid action. Must be upgrade, reinstall, or remove.")
    if not isinstance(packages, list) or not packages:
        raise HTTPException(400, "packages must be a non-empty list")
    packages = [str(p).strip() for p in packages if str(p).strip()]
    if not packages:
        raise HTTPException(400, "packages must be a non-empty list")

    job_type = {"upgrade": "pkg-upgrade", "reinstall": "pkg-reinstall", "remove": "pkg-remove"}[action]

    with transaction(db):
        created = create_job_with_runs(
            db=db,
            job_type=job_type,
            payload={"packages": packages},
            agent_ids=[agent_id],
            commit=False,
        )

        # Audit: log the intent (request) to perform a package action.
        # Do not log huge payloads; truncate package list.
        meta = {
            "action": action,
            "count": len(packages),
            "packages": packages[:20],
            "packages_truncated": len(packages) > 20,
        }
        log_event(
            db,
            action=f"packages.{action}",
            actor=user,
            request=request,
            target_type="host",
            target_id=str(agent_id),
            target_name=str(getattr(host, "hostname", None) or agent_id),
            meta=meta,
        )

    await push_job_to_agents(
        agent_ids=[agent_id],
        job_payload_builder=lambda aid: {"job_id": created.job_key, "type": job_type, "packages": packages},
    )

    return {"job_id": created.job_key, "agent_id": agent_id, "action": action, "packages": packages}


@router.get("/{agent_id}/users")
async def get_users(agent_id: str, wait: bool = True, db: Session = Depends(get_db)):
    host = db.execute(select(Host).where(Host.agent_id == agent_id)).scalar_one_or_none()
    if not host:
        raise HTTPException(404, "Host not found")

    if not is_host_online(host):
        t = seconds_since_seen(host)
        if t is not None:
            raise HTTPException(503, f"Agent appears offline (last seen {int(t)}s ago)")
        raise HTTPException(503, "Agent appears offline")

    with transaction(db):
        created = create_job_with_runs(
            db=db,
            job_type="query-users",
            payload={},
            agent_ids=[agent_id],
            commit=False,
        )
    job_id = created.job.id

    await push_job_to_agents(
        agent_ids=[agent_id],
        job_payload_builder=lambda aid: {"job_id": created.job_key, "type": "query-users"},
    )

    if not wait:
        return {"job_id": created.job_key, "status": "queued", "message": "Job queued, poll /jobs/{job_id} for results"}

    timeout = 15
    res = await wait_for_job_run(job_id=job_id, agent_id=agent_id, timeout_s=timeout, poll_interval_s=0.3)
    if not res.run:
        raise HTTPException(504, f"Timeout waiting for user query after {timeout}s")

    run = res.run
    if run.status == "failed":
        msg = run.error or run.stderr or "Unknown error"
        raise HTTPException(500, f"User query failed: {msg}")

    from ..services.json_utils import loads_or

    return loads_or(run.stdout, {})


@router.post("/{agent_id}/users/{username}/{action}")
async def control_user(
    agent_id: str,
    username: str,
    action: str,
    wait: bool = True,
    db: Session = Depends(get_db),
    user=Depends(require_ui_user),
):
    perms = permissions_for(user)
    if not perms.get("can_lock_users"):
        raise HTTPException(403, "Insufficient permissions to lock or unlock users")
    action_norm = (action or "").strip().lower()
    if action_norm not in ("lock", "unlock"):
        raise HTTPException(400, "Invalid action. Must be lock or unlock.")
    username = (username or "").strip()
    if not username:
        raise HTTPException(400, "username is required")
    if username == "root":
        raise HTTPException(400, "Cannot lock root account")

    host = db.execute(select(Host).where(Host.agent_id == agent_id)).scalar_one_or_none()
    if not host:
        raise HTTPException(404, "Host not found")

    if not is_host_online(host):
        t = seconds_since_seen(host)
        if t is not None:
            raise HTTPException(503, f"Agent appears offline (last seen {int(t)}s ago)")
        raise HTTPException(503, "Agent appears offline")

    job_type = "user-lock" if action_norm == "lock" else "user-unlock"

    with transaction(db):
        created = create_job_with_runs(
            db=db,
            job_type=job_type,
            payload={"username": username, "action": action_norm},
            agent_ids=[agent_id],
            commit=False,
        )
    job_id = created.job.id

    await push_job_to_agents(
        agent_ids=[agent_id],
        job_payload_builder=lambda aid: {
            "job_id": created.job_key,
            "type": job_type,
            "service_name": username,
        },
    )

    if not wait:
        return {"job_id": created.job_key, "status": "queued"}

    timeout = 20
    res = await wait_for_job_run(job_id=job_id, agent_id=agent_id, timeout_s=timeout, poll_interval_s=0.3)
    if not res.run:
        raise HTTPException(504, f"Timeout waiting for user {action_norm} after {timeout}s")

    run = res.run
    if run.status == "failed":
        msg = run.error or run.stderr or "Unknown error"
        raise HTTPException(500, f"User {action_norm} failed: {msg}")

    return {"job_id": created.job_key, "status": "success"}


@router.get("/{agent_id}/services")
async def get_services(agent_id: str, wait: bool = True, db: Session = Depends(get_db)):
    host = db.execute(select(Host).where(Host.agent_id == agent_id)).scalar_one_or_none()
    if not host:
        raise HTTPException(404, "Host not found")

    if not is_host_online(host):
        t = seconds_since_seen(host)
        if t is not None:
            raise HTTPException(503, f"Agent appears offline (last seen {int(t)}s ago)")
        raise HTTPException(503, "Agent appears offline")

    with transaction(db):
        created = create_job_with_runs(
            db=db,
            job_type="query-services",
            payload={},
            agent_ids=[agent_id],
            commit=False,
        )
    job_id = created.job.id

    await push_job_to_agents(
        agent_ids=[agent_id],
        job_payload_builder=lambda aid: {"job_id": created.job_key, "type": "query-services"},
    )

    if not wait:
        return {"job_id": created.job_key, "status": "queued", "message": "Job queued, poll /jobs/{job_id} for results"}

    timeout = 20
    res = await wait_for_job_run(job_id=job_id, agent_id=agent_id, timeout_s=timeout, poll_interval_s=0.3)
    if not res.run:
        raise HTTPException(504, f"Timeout waiting for services query after {timeout}s")

    run = res.run
    if run.status == "failed":
        msg = run.error or run.stderr or "Unknown error"
        raise HTTPException(500, f"Services query failed: {msg}")

    from ..services.json_utils import loads_or

    return loads_or(run.stdout, {})


@router.get("/{agent_id}/services/{service_name}")
async def get_service_details(agent_id: str, service_name: str, wait: bool = True, db: Session = Depends(get_db)):
    """Return selected systemd properties for a service."""
    host = db.execute(select(Host).where(Host.agent_id == agent_id)).scalar_one_or_none()
    if not host:
        raise HTTPException(404, "Host not found")

    if not is_host_online(host):
        t = seconds_since_seen(host)
        if t is not None:
            raise HTTPException(503, f"Agent appears offline (last seen {int(t)}s ago)")
        raise HTTPException(503, "Agent appears offline")

    with transaction(db):
        created = create_job_with_runs(
            db=db,
            job_type="query-service-details",
            payload={"service_name": service_name},
            agent_ids=[agent_id],
            commit=False,
        )
    job_id = created.job.id

    await push_job_to_agents(
        agent_ids=[agent_id],
        job_payload_builder=lambda aid: {
            "job_id": created.job_key,
            "type": "query-service-details",
            "service_name": service_name,
        },
    )

    if not wait:
        return {"job_id": created.job_key, "status": "queued"}

    timeout = 12
    res = await wait_for_job_run(job_id=job_id, agent_id=agent_id, timeout_s=timeout, poll_interval_s=0.3)
    if not res.run:
        raise HTTPException(504, f"Timeout waiting for service details after {timeout}s")

    run = res.run
    if run.status == "failed":
        msg = run.error or run.stderr or run.stdout or "Unknown error"
        raise HTTPException(500, f"Service details query failed: {msg}")

    from ..services.json_utils import loads_or

    return {"service": loads_or(run.stdout, {})}


@router.get("/{agent_id}/users/{username}")
async def get_user_details(agent_id: str, username: str, wait: bool = True, db: Session = Depends(get_db)):
    """Return detailed info about a system user (best-effort)."""
    host = db.execute(select(Host).where(Host.agent_id == agent_id)).scalar_one_or_none()
    if not host:
        raise HTTPException(404, "Host not found")

    if not is_host_online(host):
        t = seconds_since_seen(host)
        if t is not None:
            raise HTTPException(503, f"Agent appears offline (last seen {int(t)}s ago)")
        raise HTTPException(503, "Agent appears offline")

    with transaction(db):
        created = create_job_with_runs(
            db=db,
            job_type="query-user-details",
            payload={"username": username},
            agent_ids=[agent_id],
            commit=False,
        )
    job_id = created.job.id

    await push_job_to_agents(
        agent_ids=[agent_id],
        job_payload_builder=lambda aid: {
            "job_id": created.job_key,
            "type": "query-user-details",
            "service_name": username,
        },
    )

    if not wait:
        return {"job_id": created.job_key, "status": "queued"}

    timeout = 12
    res = await wait_for_job_run(job_id=job_id, agent_id=agent_id, timeout_s=timeout, poll_interval_s=0.3)
    if not res.run:
        raise HTTPException(504, f"Timeout waiting for user details after {timeout}s")

    run = res.run
    if run.status == "failed":
        msg = run.error or run.stderr or run.stdout or "Unknown error"
        raise HTTPException(500, f"User details query failed: {msg}")

    from ..services.json_utils import loads_or

    return {"user": loads_or(run.stdout, {})}


@router.get("/{agent_id}/df")
async def get_df(agent_id: str, wait: bool = True, db: Session = Depends(get_db)):
    """Return `df -h` output for the host.

    Response: {"stdout": "..."}
    """
    host = db.execute(select(Host).where(Host.agent_id == agent_id)).scalar_one_or_none()
    if not host:
        raise HTTPException(404, "Host not found")

    if not is_host_online(host):
        t = seconds_since_seen(host)
        if t is not None:
            raise HTTPException(503, f"Agent appears offline (last seen {int(t)}s ago)")
        raise HTTPException(503, "Agent appears offline")

    with transaction(db):
        created = create_job_with_runs(
            db=db,
            job_type="query-df",
            payload={},
            agent_ids=[agent_id],
            commit=False,
        )
    job_id = created.job.id

    await push_job_to_agents(
        agent_ids=[agent_id],
        job_payload_builder=lambda aid: {"job_id": created.job_key, "type": "query-df"},
    )

    if not wait:
        return {"job_id": created.job_key, "status": "queued", "message": "Job queued, poll /jobs/{job_id} for results"}

    timeout = 12
    res = await wait_for_job_run(job_id=job_id, agent_id=agent_id, timeout_s=timeout, poll_interval_s=0.3)
    if not res.run:
        raise HTTPException(504, f"Timeout waiting for df query after {timeout}s")

    run = res.run
    if run.status == "failed":
        msg = run.error or run.stderr or run.stdout or "Unknown error"
        raise HTTPException(500, f"df query failed: {msg}")

    return {"stdout": run.stdout or ""}


@router.get("/{agent_id}/metrics")
async def get_metrics(agent_id: str, wait: bool = True, db: Session = Depends(get_db)):
    """Fetch basic host metrics (disk/mem/cpu/load/ips).

    UI expects a *flat* JSON object with keys like disk_usage, memory, cpu, ip_addresses.
    The agent returns {"metrics": {...}}, so unwrap it.
    """
    host = db.execute(select(Host).where(Host.agent_id == agent_id)).scalar_one_or_none()
    if not host:
        raise HTTPException(404, "Host not found")

    if not is_host_online(host):
        t = seconds_since_seen(host)
        if t is not None:
            raise HTTPException(503, f"Agent appears offline (last seen {int(t)}s ago)")
        raise HTTPException(503, "Agent appears offline")

    with transaction(db):
        created = create_job_with_runs(
            db=db,
            job_type="query-metrics",
            payload={},
            agent_ids=[agent_id],
            commit=False,
        )
    job_id = created.job.id

    await push_job_to_agents(
        agent_ids=[agent_id],
        job_payload_builder=lambda aid: {"job_id": created.job_key, "type": "query-metrics"},
    )

    if not wait:
        return {"job_id": created.job_key, "status": "queued", "message": "Job queued, poll /jobs/{job_id} for results"}

    timeout = 12
    res = await wait_for_job_run(job_id=job_id, agent_id=agent_id, timeout_s=timeout, poll_interval_s=0.3)
    if not res.run:
        raise HTTPException(504, f"Timeout waiting for metrics query after {timeout}s")

    run = res.run
    if run.status == "failed":
        msg = run.error or run.stderr or "Unknown error"
        raise HTTPException(500, f"Metrics query failed: {msg}")

    from ..services.json_utils import loads_or

    payload = loads_or(run.stdout, {})
    if isinstance(payload, dict) and isinstance(payload.get("metrics"), dict):
        metrics = payload["metrics"]
        # Persist a lightweight metrics snapshot + load history so overview checks can be fast.
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

            # Retention: keep last 7 days per host
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
            # Don't break metrics endpoint if persistence fails.
            db.rollback()
        return metrics
    # Backwards-compat or unexpected agent output
    return payload if isinstance(payload, dict) else {}


@router.get("/{agent_id}/load-history")
def get_load_history(
    agent_id: str,
    since_seconds: int = 3600,
    limit: int = 600,
    db: Session = Depends(get_db),
):
    """Return historical load data for the UI graph.

    Response shape: {"history": [{"time": <iso>, "load_1min": <float>, "load_5min": <float>, "load_15min": <float>}]}.
    """
    if since_seconds < 10:
        since_seconds = 10
    if since_seconds > 60 * 60 * 24 * 30:
        since_seconds = 60 * 60 * 24 * 30

    if limit < 1:
        limit = 1
    if limit > 5000:
        limit = 5000

    # Ensure host exists (helps catch typos)
    host = db.execute(select(Host).where(Host.agent_id == agent_id)).scalar_one_or_none()
    if not host:
        raise HTTPException(404, "Host not found")

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
async def get_top_processes(agent_id: str, wait: bool = True, db: Session = Depends(get_db)):
    """Fetch top processes by CPU (fast polling endpoint used by UI)."""
    host = db.execute(select(Host).where(Host.agent_id == agent_id)).scalar_one_or_none()
    if not host:
        raise HTTPException(404, "Host not found")

    if not is_host_online(host):
        t = seconds_since_seen(host)
        if t is not None:
            raise HTTPException(503, f"Agent appears offline (last seen {int(t)}s ago)")
        raise HTTPException(503, "Agent appears offline")

    with transaction(db):
        created = create_job_with_runs(
            db=db,
            job_type="query-top-processes",
            payload={},
            agent_ids=[agent_id],
            commit=False,
        )
    job_id = created.job.id

    await push_job_to_agents(
        agent_ids=[agent_id],
        job_payload_builder=lambda aid: {"job_id": created.job_key, "type": "query-top-processes"},
    )

    if not wait:
        return {"job_id": created.job_key, "status": "queued", "message": "Job queued, poll /jobs/{job_id} for results"}

    timeout = 6
    res = await wait_for_job_run(job_id=job_id, agent_id=agent_id, timeout_s=timeout, poll_interval_s=0.2)
    if not res.run:
        raise HTTPException(504, f"Timeout waiting for top-processes after {timeout}s")

    run = res.run
    if run.status == "failed":
        msg = run.error or run.stderr or "Unknown error"
        raise HTTPException(500, f"Top processes query failed: {msg}")

    from ..services.json_utils import loads_or

    payload = loads_or(run.stdout, {})
    if isinstance(payload, dict) and "top_processes" in payload:
        return payload
    return {"top_processes": []}
