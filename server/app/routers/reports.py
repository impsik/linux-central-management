from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import case, func, select
from sqlalchemy.orm import Session

from ..config import settings
from ..db import get_db
from ..deps import require_ui_user
from ..models import Host, HostPackageUpdate
from ..services.cve_reporting import collect_high_severity_findings
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
    visible = []
    for item in findings:
        host = db.execute(select(Host).where(Host.id == item.host_id)).scalar_one_or_none()
        if host and is_host_visible_to_user(db, user, host):
            visible.append(item)

    reverse = order == "desc"
    key_map = {
        "severity": lambda item: (item.severity, item.hostname, item.package_name, item.cve_id),
        "hostname": lambda item: (item.hostname, item.severity, item.package_name, item.cve_id),
        "package_name": lambda item: (item.package_name, item.severity, item.hostname, item.cve_id),
        "cve_id": lambda item: (item.cve_id, item.severity, item.hostname, item.package_name),
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
                "fixed_version": item.fixed_version,
                "cve_id": item.cve_id,
                "severity": item.severity,
                "release": item.release,
            }
            for item in rows
        ],
    }
