"""Read-only first-host setup progress, restricted to administrators."""
from fastapi import APIRouter, Depends, Query
from fastapi.responses import JSONResponse
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from ..db import get_db
from ..deps import require_admin_user
from ..models import Host, HostPackage, HostPackageUpdate
from ..services.hosts import is_host_online

router = APIRouter(prefix="/onboarding", tags=["onboarding"])


@router.get("/status")
def onboarding_status(
    target: str = Query(default="", max_length=253),
    db: Session = Depends(get_db),
    user=Depends(require_admin_user),
):
    total = db.scalar(select(func.count()).select_from(Host)) or 0
    query = select(Host)
    if target.strip():
        target = target.strip().lower()
        query = query.where(or_(
            func.lower(Host.hostname) == target,
            func.lower(Host.fqdn) == target,
            Host.ip_address == target,
            func.lower(Host.agent_id) == target,
        ))
    host = db.scalars(query.order_by(Host.created_at, Host.id).limit(1)).first()
    data = {"host_count": total, "host": None}
    if host:
        package_count, collected_at = db.execute(
            select(func.count(), func.max(HostPackage.collected_at))
            .where(HostPackage.host_id == host.id)
        ).one()
        updates = db.scalar(select(func.count()).select_from(HostPackageUpdate).where(
            HostPackageUpdate.host_id == host.id,
            HostPackageUpdate.update_available.is_(True),
        )) or 0
        data["host"] = {
            "agent_id": host.agent_id,
            "hostname": host.hostname,
            "os_id": host.os_id,
            "os_version": host.os_version,
            "online": is_host_online(host),
            "last_seen": host.last_seen.isoformat() if host.last_seen else None,
            "package_count": package_count,
            "inventory_received": collected_at is not None,
            "inventory_at": collected_at.isoformat() if collected_at else None,
            "updates_count": updates,
        }
    return JSONResponse(data, headers={"Cache-Control": "no-store"})
