from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import case, func, select
from sqlalchemy.orm import Session

from ..config import settings
from ..db import get_db
from ..deps import require_ui_user
from ..models import Host, HostPackageUpdate

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

    # Aggregate updates per host
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
        # Keep hosts that have at least one pending update
        q = q.having(updates_total > 0)

    # Order by
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

    total = db.execute(select(func.count()).select_from(q.subquery())).scalar_one()

    rows = db.execute(q.limit(limit).offset(offset)).all()

    items = []
    for r in rows:
        # online hint
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
