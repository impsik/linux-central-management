from __future__ import annotations

from datetime import datetime, timezone
import json

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import and_, delete, func, or_, select
from sqlalchemy.orm import Session

from ..db import get_db
from ..deps import require_ui_user
from ..models import CVEPackage, Host, HostPackage, HostPackageUpdate
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
from ..services.jobs import create_job_with_runs, push_job_to_agents
from ..services.package_names import sanitize_package_list
from ..services.deb_version import is_vulnerable

router = APIRouter(prefix="/hosts", tags=["hosts"])


@router.get("/{agent_id}/packages")
def list_host_packages(
    agent_id: str,
    search: str | None = None,
    upgradable_only: bool = False,
    cves_only: bool = False,
    limit: int = 500,
    offset: int = 0,
    db: Session = Depends(get_db),
    user=Depends(require_ui_user),
):
    if limit < 1:
        limit = 1
    if limit > 2000:
        limit = 2000
    if offset < 0:
        offset = 0

    host = get_visible_host_or_404(db, user, agent_id)

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

    base_query_limit = 10000 if cves_only else limit
    base_query_offset = 0 if cves_only else offset

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
            .limit(base_query_limit)
            .offset(base_query_offset)
        ).scalars().all()
    else:
        rows = db.execute(
            select(HostPackage)
            .where(*base_filter)
            .order_by(HostPackage.name.asc())
            .limit(base_query_limit)
            .offset(base_query_offset)
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

    release_codename = None
    if host.os_version:
        v = host.os_version.lower()
        if "20.04" in v or "focal" in v:
            release_codename = "focal"
        elif "22.04" in v or "jammy" in v:
            release_codename = "jammy"
        elif "24.04" in v or "noble" in v:
            release_codename = "noble"

    pkg_cves = {}
    if release_codename and names:
        cve_rows = db.execute(
            select(CVEPackage)
            .where(
                CVEPackage.release == release_codename,
                CVEPackage.package_name.in_(names)
            )
        ).scalars().all()

        for c in cve_rows:
            pkg_ver = None
            for r in rows:
                if r.name == c.package_name:
                    pkg_ver = r.version
                    break

            if pkg_ver and is_vulnerable(pkg_ver, c.fixed_version):
                if c.package_name not in pkg_cves:
                    pkg_cves[c.package_name] = []
                pkg_cves[c.package_name].append(c.cve_id)

    if cves_only:
        rows = [r for r in rows if pkg_cves.get(r.name)]
        total = len(rows)
        if offset:
            rows = rows[offset:]
        if limit:
            rows = rows[:limit]

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
                "cves": pkg_cves.get(r.name, [])
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
async def get_package_info(agent_id: str, pkg_name: str, wait: bool = True, db: Session = Depends(get_db), user=Depends(require_ui_user)):
    host = get_visible_host_or_404(db, user, agent_id)

    if not is_host_online(host):
        t = seconds_since_seen(host)
        if t is not None:
            raise HTTPException(503, f"Agent appears offline (last seen {int(t)}s ago)")
        raise HTTPException(503, "Agent appears offline")

    pkg_name = (pkg_name or "").strip()
    if not pkg_name:
        raise HTTPException(400, "Package name is required")

    created, job_id, push_kwargs = dispatch_host_job(
        db=db,
        agent_id=agent_id,
        job_type="query-pkg-info",
        payload={"package_name": pkg_name},
    )

    await push_dispatched_host_job(push_kwargs=push_kwargs)

    if not wait:
        return {"job_id": created.job_key, "status": "queued"}

    timeout = 20
    run = await wait_for_host_job_or_504(
        job_id=job_id,
        agent_id=agent_id,
        timeout_s=timeout,
        timeout_message=f"Timeout waiting for package info after {timeout}s",
    )
    require_successful_run(run, error_message="Package info query failed")
    return parse_json_run_stdout(run, {})


@router.post("/{agent_id}/packages/check-updates")
async def check_host_package_updates(agent_id: str, refresh: bool = True, wait: bool = True, db: Session = Depends(get_db), user=Depends(require_ui_user)):
    host = get_visible_host_or_404(db, user, agent_id)

    created, job_id, push_kwargs = dispatch_host_job(
        db=db,
        agent_id=agent_id,
        job_type="query-pkg-updates",
        payload={"refresh": refresh},
    )

    await push_dispatched_host_job(push_kwargs=push_kwargs)

    if not wait:
        return {"job_id": created.job_key, "status": "queued"}

    timeout = 35 if refresh else 15
    run = await wait_for_host_job_or_504(
        job_id=job_id,
        agent_id=agent_id,
        timeout_s=timeout,
        timeout_message=f"Timeout waiting for update check after {timeout}s",
    )
    require_successful_run(run, error_message="Update check failed")

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
async def refresh_host_packages(agent_id: str, wait: bool = False, db: Session = Depends(get_db), user=Depends(require_ui_user)):
    get_visible_host_or_404(db, user, agent_id)

    created, job_id, push_kwargs = dispatch_host_job(
        db=db,
        agent_id=agent_id,
        job_type="inventory-now",
        payload={},
    )

    await push_dispatched_host_job(push_kwargs=push_kwargs)

    if not wait:
        return {"job_id": created.job_key, "status": "queued"}

    timeout = 90
    run = await wait_for_host_job_or_504(
        job_id=job_id,
        agent_id=agent_id,
        timeout_s=timeout,
        timeout_message=f"Timeout waiting for inventory refresh after {timeout}s",
    )
    require_successful_run(run, error_message="Inventory refresh failed")
    return {"job_id": created.job_key, "status": "success"}


@router.post("/{agent_id}/packages/action")
async def host_packages_action(
    agent_id: str,
    payload: dict,
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(require_ui_user),
):
    host = get_visible_host_or_404(db, user, agent_id)

    action = (payload.get("action") or "").strip()
    packages = payload.get("packages") or []
    if action not in ("upgrade", "reinstall", "remove"):
        raise HTTPException(400, "Invalid action. Must be upgrade, reinstall, or remove.")
    if not isinstance(packages, list) or not packages:
        raise HTTPException(400, "packages must be a non-empty list")
    packages = sanitize_package_list(packages)
    if not packages:
        raise HTTPException(400, "packages must contain valid package names")

    job_type = {"upgrade": "pkg-upgrade", "reinstall": "pkg-reinstall", "remove": "pkg-remove"}[action]

    with transaction(db):
        created = create_job_with_runs(
            db=db,
            job_type=job_type,
            payload={"packages": packages},
            agent_ids=[agent_id],
            commit=False,
        )

        meta = {
            "action": action,
            "count": len(packages),
            "packages": packages[:20],
            "packages_truncated": len(packages) > 20,
        }
        from ..services.audit import log_event

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
