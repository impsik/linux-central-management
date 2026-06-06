from __future__ import annotations

import asyncio
import time
from datetime import datetime, timezone
from types import SimpleNamespace

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel
from sqlalchemy import case, delete, func, select
from sqlalchemy.orm import Session

from ..config import settings
from ..db import SessionLocal, get_db
from ..deps import require_ui_user
from ..models import Host, HostPackageUpdate, HostUser, JobRun
from ..services.cve_reporting import collect_high_severity_findings, merge_findings_by_package
from ..services.db_utils import transaction
from ..services.audit import log_event
from ..services.hosts import is_host_online
from ..services.jobs import create_job_with_runs, push_job_to_agents
from ..services.json_utils import loads_or
from ..services.rbac import permissions_for
from ..services.user_scopes import is_host_visible_to_user

router = APIRouter(prefix="/reports", tags=["reports"])

ALLOWED_SORT = {
    "hostname": "hostname",
    "agent_id": "agent_id",
    "os_version": "os_version",
    "kernel": "kernel",
    "updates": "updates",
    "security_updates": "security_updates",
    "last_seen": "last_seen",
}

ALLOWED_CVE_SORT = {
    "severity": "severity",
    "hostname": "hostname",
    "package_name": "package_name",
    "cve_id": "cve_id",
}


class UserPresenceActionRequest(BaseModel):
    username: str
    agent_ids: list[str] | None = None


class ServicePresenceActionRequest(BaseModel):
    service_name: str
    agent_ids: list[str] | None = None


async def _wait_for_job_runs(
    *,
    job_id,
    agent_ids: list[str],
    timeout_s: float,
    poll_interval_s: float = 0.5,
) -> list[JobRun]:
    wanted = sorted({str(a) for a in agent_ids if str(a).strip()})
    start = time.time()
    while time.time() - start < timeout_s:
        db = SessionLocal()
        try:
            rows = db.execute(
                select(JobRun).where(JobRun.job_id == job_id, JobRun.agent_id.in_(wanted))
            ).scalars().all()
            done = [r for r in rows if r.status in ("success", "failed")]
            if len(done) >= len(wanted):
                for r in done:
                    db.expunge(r)
                return done
        finally:
            db.close()
        await asyncio.sleep(poll_interval_s)

    db = SessionLocal()
    try:
        rows = db.execute(
            select(JobRun).where(JobRun.job_id == job_id, JobRun.agent_id.in_(wanted))
        ).scalars().all()
        for r in rows:
            db.expunge(r)
        return rows
    finally:
        db.close()


def _visible_online_hosts(
    *,
    db: Session,
    user,
    agent_ids: list[str] | None = None,
    max_hosts: int = 200,
) -> tuple[list[Host], list[str]]:
    now = datetime.now(timezone.utc)
    requested = {str(a).strip() for a in (agent_ids or []) if str(a).strip()}
    stmt = select(Host).order_by(Host.hostname.asc(), Host.agent_id.asc())
    if requested:
        stmt = stmt.where(Host.agent_id.in_(requested))
    hosts = db.execute(stmt.limit(max_hosts)).scalars().all()

    visible_online: list[Host] = []
    skipped_offline: list[str] = []
    for h in hosts:
        if not is_host_visible_to_user(db, user, h):
            continue
        if is_host_online(h, now):
            visible_online.append(h)
        else:
            skipped_offline.append(h.agent_id)
    return visible_online, skipped_offline


async def _refresh_user_presence_live(
    *,
    db: Session,
    user,
    username: str,
    exact: bool,
    agent_ids: list[str] | None = None,
    max_hosts: int = 120,
) -> dict:
    hosts, skipped_offline = _visible_online_hosts(db=db, user=user, agent_ids=agent_ids, max_hosts=max_hosts)
    if not hosts:
        return {"scanned_hosts": 0, "failed_hosts": 0, "skipped_offline": skipped_offline}

    targets = [h.agent_id for h in hosts]
    host_by_agent = {h.agent_id: h for h in hosts}
    with transaction(db):
        created = create_job_with_runs(
            db=db,
            job_type="query-users",
            payload={"source": "user-presence-live-refresh", "username": username, "exact": exact},
            agent_ids=targets,
            commit=False,
        )

    await push_job_to_agents(
        agent_ids=targets,
        job_payload_builder=lambda aid: {"job_id": created.job_key, "type": "query-users"},
    )

    runs = await _wait_for_job_runs(job_id=created.job.id, agent_ids=targets, timeout_s=20, poll_interval_s=0.5)
    failed_hosts = 0
    for run in runs:
        if run.status != "success" or not run.stdout:
            failed_hosts += 1
            continue
        h = host_by_agent.get(run.agent_id)
        if not h:
            continue
        data = loads_or(run.stdout, {})
        users = data.get("users") or []
        with transaction(db):
            db.execute(delete(HostUser).where(HostUser.host_id == h.id))
            for item in users:
                uname = str(item.get("username") or "").strip()
                if not uname:
                    continue
                db.add(
                    HostUser(
                        host_id=h.id,
                        username=uname,
                        uid=(int(item.get("uid")) if str(item.get("uid") or "").isdigit() else None),
                        gid=(int(item.get("gid")) if str(item.get("gid") or "").isdigit() else None),
                        home=(item.get("home") or "")[:512],
                        shell=(item.get("shell") or "")[:128],
                        has_sudo=bool(item.get("has_sudo", False)),
                        is_locked=bool(item.get("is_locked", False)),
                    )
                )

    return {"scanned_hosts": len(hosts), "failed_hosts": failed_hosts, "skipped_offline": skipped_offline}


def _user_presence_rows(
    *,
    db: Session,
    user,
    username: str,
    exact: bool = True,
    online_only: bool = False,
    limit: int = 500,
    offset: int = 0,
) -> tuple[int, list[dict]]:
    u = (username or "").strip()
    if not u:
        raise HTTPException(400, "username is required")
    if limit < 1:
        limit = 1
    if limit > 5000:
        limit = 5000
    if offset < 0:
        offset = 0

    if exact:
        stmt = (
            select(HostUser, Host)
            .join(Host, Host.id == HostUser.host_id)
            .where(func.lower(HostUser.username) == u.lower())
            .order_by(Host.hostname.asc(), Host.agent_id.asc())
            .limit(5000)
        )
    else:
        stmt = (
            select(HostUser, Host)
            .join(Host, Host.id == HostUser.host_id)
            .where(func.lower(HostUser.username).like(f"%{u.lower()}%"))
            .order_by(Host.hostname.asc(), Host.agent_id.asc())
            .limit(5000)
        )

    rows: list[dict] = []
    now = datetime.now(timezone.utc)
    for hu, h in db.execute(stmt).all():
        if not is_host_visible_to_user(db, user, h):
            continue
        host_online = is_host_online(h, now)
        if online_only and not host_online:
            continue
        rows.append(
            {
                "agent_id": h.agent_id,
                "hostname": h.hostname,
                "fqdn": h.fqdn,
                "ip_address": h.ip_address,
                "os_id": h.os_id,
                "os_version": h.os_version,
                "labels": h.labels or {},
                "last_seen": h.last_seen,
                "is_online": host_online,
                "username": hu.username,
                "uid": hu.uid,
                "gid": hu.gid,
                "home": hu.home,
                "shell": hu.shell,
                "has_sudo": bool(getattr(hu, "has_sudo", False)),
                "is_locked": bool(getattr(hu, "is_locked", False)),
                "user_last_seen": hu.last_seen,
            }
        )

    total = len(rows)
    return total, rows[offset:offset + limit]


@router.get("/hosts-updates")
def hosts_updates_report(
    only_pending: bool = True,
    online_only: bool = False,
    sort: str = "security_updates",
    order: str = "desc",
    limit: int = 500,
    offset: int = 0,
    db: Session = Depends(get_db),
    user=Depends(require_ui_user),
):
    """Report: per-host counts of pending updates.

    Returns one row per host with:
      - total pending updates count
      - security pending updates count

    Sorting is server-side.
    """

    if limit < 1:
        limit = 1
    if limit > 5000:
        limit = 5000
    if offset < 0:
        offset = 0

    sort = (sort or "").strip()
    order = (order or "").strip().lower()
    if sort not in ALLOWED_SORT:
        raise HTTPException(400, f"invalid sort (allowed: {', '.join(sorted(ALLOWED_SORT))})")
    if order not in ("asc", "desc"):
        raise HTTPException(400, "invalid order (asc|desc)")

    now = datetime.now(timezone.utc)
    grace_s = int(getattr(settings, "agent_online_grace_seconds", 10) or 10)
    online_cutoff = now.timestamp() - grace_s

    updates_total = func.coalesce(
        func.sum(case((HostPackageUpdate.update_available == True, 1), else_=0)),  # noqa: E712
        0,
    ).label("updates")
    updates_security = func.coalesce(
        func.sum(
            case(
                (
                    (HostPackageUpdate.update_available == True) & (HostPackageUpdate.is_security == True),  # noqa: E712
                    1,
                ),
                else_=0,
            )
        ),
        0,
    ).label("security_updates")

    q = (
        select(
            Host.agent_id,
            Host.hostname,
            Host.fqdn,
            Host.ip_address,
            Host.os_id,
            Host.os_version,
            Host.kernel,
            Host.labels,
            Host.last_seen,
            Host.reboot_required,
            updates_total,
            updates_security,
        )
        .select_from(Host)
        .outerjoin(HostPackageUpdate, HostPackageUpdate.host_id == Host.id)
        .group_by(Host.id)
    )

    if online_only:
        q = q.where(Host.last_seen.is_not(None), func.extract("epoch", Host.last_seen) >= online_cutoff)

    if only_pending:
        q = q.having(updates_total > 0)

    sort_col_map = {
        "hostname": Host.hostname,
        "agent_id": Host.agent_id,
        "os_version": Host.os_version,
        "kernel": Host.kernel,
        "updates": updates_total,
        "security_updates": updates_security,
        "last_seen": Host.last_seen,
    }
    col = sort_col_map[sort]
    q = q.order_by(col.asc() if order == "asc" else col.desc())

    all_rows = db.execute(q).all()
    visible_rows = [
        r for r in all_rows
        if is_host_visible_to_user(db, user, SimpleNamespace(labels=r.labels or {}))
    ]
    total = len(visible_rows)
    rows = visible_rows[offset:offset + limit]

    items = []
    for r in rows:
        is_online = False
        if r.last_seen is not None:
            try:
                is_online = float(r.last_seen.timestamp()) >= online_cutoff
            except Exception:
                is_online = False

        items.append(
            {
                "agent_id": r.agent_id,
                "hostname": r.hostname,
                "fqdn": r.fqdn,
                "ip_address": r.ip_address,
                "os_id": r.os_id,
                "os_version": r.os_version,
                "kernel": r.kernel,
                "labels": r.labels or {},
                "last_seen": r.last_seen,
                "is_online": is_online,
                "reboot_required": bool(getattr(r, "reboot_required", False)),
                "updates": int(r.updates or 0),
                "security_updates": int(r.security_updates or 0),
            }
        )

    return {
        "ts": now.isoformat(),
        "total": int(total or 0),
        "limit": limit,
        "offset": offset,
        "items": items,
    }


@router.get("/cve-high-severity")
def cve_high_severity_report(
    min_severity: float = 7.0,
    sort: str = "severity",
    order: str = "desc",
    limit: int = 500,
    offset: int = 0,
    db: Session = Depends(get_db),
    user=Depends(require_ui_user),
):
    if limit < 1:
        limit = 1
    if limit > 5000:
        limit = 5000
    if offset < 0:
        offset = 0

    sort = (sort or "severity").strip()
    order = (order or "desc").strip().lower()
    if sort not in ALLOWED_CVE_SORT:
        raise HTTPException(400, f"invalid sort (allowed: {', '.join(sorted(ALLOWED_CVE_SORT))})")
    if order not in ("asc", "desc"):
        raise HTTPException(400, "invalid order (asc|desc)")

    findings = collect_high_severity_findings(db, min_severity=float(min_severity))
    package_findings = merge_findings_by_package(findings)
    visible = []
    for item in package_findings:
        host = db.execute(select(Host).where(Host.id == item.host_id)).scalar_one_or_none()
        if host and is_host_visible_to_user(db, user, host):
            visible.append(item)

    reverse = order == "desc"
    key_map = {
        "severity": lambda item: (item.severity, item.hostname, item.package_name, item.cve_ids[0] if item.cve_ids else ""),
        "hostname": lambda item: (item.hostname, item.severity, item.package_name, item.cve_ids[0] if item.cve_ids else ""),
        "package_name": lambda item: (item.package_name, item.severity, item.hostname, item.cve_ids[0] if item.cve_ids else ""),
        "cve_id": lambda item: (item.cve_ids[0] if item.cve_ids else "", item.severity, item.hostname, item.package_name),
    }
    visible.sort(key=key_map[sort], reverse=reverse)

    total = len(visible)
    rows = visible[offset:offset + limit]

    return {
        "ts": datetime.now(timezone.utc).isoformat(),
        "min_severity": float(min_severity),
        "total": total,
        "limit": limit,
        "offset": offset,
        "items": [
            {
                "agent_id": item.agent_id,
                "hostname": item.hostname,
                "package_name": item.package_name,
                "installed_version": item.installed_version,
                "candidate_version": item.candidate_version,
                "candidate_fixes": item.candidate_fixes,
                "fixed_version": item.fixed_version,
                "cve_id": item.cve_ids[0] if item.cve_ids else None,
                "cve_ids": list(item.cve_ids),
                "cve_count": item.cve_count,
                "severity": item.severity,
                "release": item.release,
            }
            for item in rows
        ],
    }


@router.get("/user-presence")
async def user_presence_report(
    username: str,
    exact: bool = True,
    online_only: bool = False,
    live_scan: bool = False,
    agent_ids: list[str] | None = Query(None),
    limit: int = 500,
    offset: int = 0,
    db: Session = Depends(get_db),
    user=Depends(require_ui_user),
):
    live = None
    if live_scan:
        live = await _refresh_user_presence_live(
            db=db,
            user=user,
            username=username,
            exact=exact,
            agent_ids=agent_ids,
        )

    total, rows = _user_presence_rows(
        db=db,
        user=user,
        username=username,
        exact=exact,
        online_only=online_only,
        limit=limit,
        offset=offset,
    )
    return {
        "ts": datetime.now(timezone.utc).isoformat(),
        "username": (username or "").strip(),
        "exact": bool(exact),
        "online_only": bool(online_only),
        "live_scan": bool(live_scan),
        "live": live,
        "total": total,
        "limit": limit,
        "offset": offset,
        "items": rows,
    }


@router.get("/service-presence")
async def service_presence_report(
    service_name: str,
    exact: bool = True,
    max_hosts: int = Query(200, ge=1, le=500),
    db: Session = Depends(get_db),
    user=Depends(require_ui_user),
):
    service_query = (service_name or "").strip()
    if not service_query:
        raise HTTPException(400, "service_name is required")
    service_query_norm = service_query.removesuffix(".service").lower()

    hosts, skipped_offline = _visible_online_hosts(db=db, user=user, max_hosts=max_hosts)
    targets = [h.agent_id for h in hosts]
    if not targets:
        return {
            "ts": datetime.now(timezone.utc).isoformat(),
            "service_name": service_query,
            "exact": bool(exact),
            "total": 0,
            "items": [],
            "scanned_hosts": 0,
            "skipped_offline": skipped_offline,
            "failed_hosts": [],
        }

    host_by_agent = {h.agent_id: h for h in hosts}
    with transaction(db):
        created = create_job_with_runs(
            db=db,
            job_type="query-services",
            payload={"source": "service-presence", "service_name": service_query, "exact": exact},
            agent_ids=targets,
            commit=False,
        )

    await push_job_to_agents(
        agent_ids=targets,
        job_payload_builder=lambda aid: {"job_id": created.job_key, "type": "query-services"},
    )

    runs = await _wait_for_job_runs(job_id=created.job.id, agent_ids=targets, timeout_s=25, poll_interval_s=0.5)
    failed_hosts: list[str] = []
    items: list[dict] = []
    for run in runs:
        if run.status != "success" or not run.stdout:
            failed_hosts.append(run.agent_id)
            continue
        h = host_by_agent.get(run.agent_id)
        if not h:
            continue
        data = loads_or(run.stdout, {})
        for svc in data.get("services") or []:
            name = str(svc.get("name") or "").strip()
            if not name:
                continue
            name_norm = name.removesuffix(".service").lower()
            if exact and name_norm != service_query_norm:
                continue
            if (not exact) and service_query_norm not in name_norm:
                continue
            items.append(
                {
                    "agent_id": h.agent_id,
                    "hostname": h.hostname,
                    "fqdn": h.fqdn,
                    "ip_address": h.ip_address,
                    "os_id": h.os_id,
                    "os_version": h.os_version,
                    "labels": h.labels or {},
                    "last_seen": h.last_seen,
                    "is_online": True,
                    "service_name": name,
                    "status": str(svc.get("status") or ""),
                    "enabled": bool(svc.get("enabled", False)),
                    "description": str(svc.get("description") or ""),
                }
            )

    items.sort(key=lambda it: (str(it.get("hostname") or it.get("agent_id") or ""), str(it.get("service_name") or "")))
    return {
        "ts": datetime.now(timezone.utc).isoformat(),
        "service_name": service_query,
        "exact": bool(exact),
        "total": len(items),
        "items": items,
        "scanned_hosts": len(targets),
        "skipped_offline": skipped_offline,
        "failed_hosts": sorted(failed_hosts),
    }


@router.post("/service-presence/{action}")
async def service_presence_action(
    action: str,
    payload: ServicePresenceActionRequest,
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(require_ui_user),
):
    perms = permissions_for(user)
    if not perms.get("can_manage_services"):
        raise HTTPException(403, "Insufficient permissions to manage services")

    action_norm = (action or "").strip().lower()
    if action_norm not in ("start", "stop", "disable", "enable"):
        raise HTTPException(400, "Invalid action. Must be start, stop, disable, or enable.")

    service_name = (payload.service_name or "").strip()
    if not service_name:
        raise HTTPException(400, "service_name is required")

    requested = sorted({str(a).strip() for a in (payload.agent_ids or []) if str(a).strip()})
    if not requested:
        raise HTTPException(400, "agent_ids is required")

    hosts, skipped_offline = _visible_online_hosts(db=db, user=user, agent_ids=requested, max_hosts=500)
    targets = sorted({h.agent_id for h in hosts})
    unknown_or_unavailable = sorted(set(requested) - set(targets) - set(skipped_offline))
    if not targets:
        raise HTTPException(400, "No online matching hosts selected for this service action")

    with transaction(db):
        created = create_job_with_runs(
            db=db,
            job_type="service-control",
            payload={"service_name": service_name, "action": action_norm, "source": "service-presence"},
            agent_ids=targets,
            commit=False,
        )

    await push_job_to_agents(
        agent_ids=targets,
        job_payload_builder=lambda aid: {
            "job_id": created.job_key,
            "type": "service-control",
            "service_name": service_name,
            "action": action_norm,
        },
    )

    with transaction(db):
        log_event(
            db,
            action=f"reports.service_presence.{action_norm}",
            actor=user,
            request=request,
            target_type="service",
            target_name=service_name,
            meta={
                "job_id": created.job_key,
                "target_count": len(targets),
                "offline_agent_ids": skipped_offline,
                "unknown_or_unavailable_agent_ids": unknown_or_unavailable,
            },
        )

    return {
        "job_id": created.job_key,
        "action": action_norm,
        "service_name": service_name,
        "targets": targets,
        "skipped_offline": sorted(skipped_offline),
        "unknown_or_unavailable": unknown_or_unavailable,
    }


@router.post("/user-presence/{action}")
async def user_presence_action(
    action: str,
    payload: UserPresenceActionRequest,
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(require_ui_user),
):
    perms = permissions_for(user)
    if not perms.get("can_lock_users"):
        raise HTTPException(403, "Insufficient permissions to lock or unlock users")

    action_norm = (action or "").strip().lower()
    if action_norm not in ("lock", "unlock"):
        raise HTTPException(400, "Invalid action. Must be lock or unlock.")

    username = (payload.username or "").strip()
    if not username:
        raise HTTPException(400, "username is required")
    if username == "root":
        raise HTTPException(400, "Cannot lock root account")

    total, rows = _user_presence_rows(
        db=db,
        user=user,
        username=username,
        exact=True,
        online_only=False,
        limit=5000,
        offset=0,
    )

    requested = {str(a).strip() for a in (payload.agent_ids or []) if str(a).strip()}
    matched_agent_ids = {str(r["agent_id"]) for r in rows if r.get("agent_id")}
    if requested:
        unknown = sorted(requested - matched_agent_ids)
        target_rows = [r for r in rows if str(r.get("agent_id") or "") in requested]
    else:
        unknown = []
        target_rows = list(rows)

    offline = sorted({str(r["agent_id"]) for r in target_rows if not r.get("is_online")})
    targets = sorted({str(r["agent_id"]) for r in target_rows if r.get("is_online")})
    if not targets:
        raise HTTPException(400, "No online matching hosts found for this user")

    job_type = "user-lock" if action_norm == "lock" else "user-unlock"
    with transaction(db):
        created = create_job_with_runs(
            db=db,
            job_type=job_type,
            payload={"username": username, "action": action_norm, "source": "user-presence"},
            agent_ids=targets,
            commit=False,
        )

    await push_job_to_agents(
        agent_ids=targets,
        job_payload_builder=lambda aid: {
            "job_id": created.job_key,
            "type": job_type,
            "service_name": username,
        },
    )

    with transaction(db):
        log_event(
            db,
            action=f"reports.user_presence.{action_norm}",
            actor=user,
            request=request,
            target_type="system_user",
            target_name=username,
            meta={
                "job_id": created.job_key,
                "target_count": len(targets),
                "matched_count": total,
                "offline_agent_ids": offline,
                "unknown_or_unmatched_agent_ids": unknown,
            },
        )

    return {
        "job_id": created.job_key,
        "action": action_norm,
        "username": username,
        "targets": targets,
        "skipped_offline": offline,
        "unknown_or_unmatched": unknown,
    }
