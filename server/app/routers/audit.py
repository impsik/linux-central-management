from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import get_db
from ..deps import require_ui_user
from ..models import AuditEvent, AppUser
from ..services.rbac import permissions_for

router = APIRouter(prefix="/audit", tags=["audit"])


@router.get("")
def list_audit(
    request: Request,
    action: str | None = None,
    actor: str | None = None,
    limit: int = 200,
    db: Session = Depends(get_db),
    user: AppUser = Depends(require_ui_user),
):
    perms = permissions_for(user)
    if (perms.get("role") or "operator") != "admin":
        raise HTTPException(403, "Admin privileges required")

    if limit < 1:
        limit = 1
    if limit > 500:
        limit = 500

    q = select(AuditEvent).order_by(AuditEvent.created_at.desc())
    if action:
        q = q.where(AuditEvent.action == action)
    if actor:
        q = q.where(AuditEvent.actor_username == actor)

    rows = db.execute(q.limit(limit)).scalars().all()

    items = []
    for e in rows:
        items.append(
            {
                "id": str(e.id),
                "action": e.action,
                "actor": e.actor_username,
                "role": e.actor_role,
                "ip": e.ip_address,
                "target_type": e.target_type,
                "target_name": e.target_name,
                "created_at": e.created_at.isoformat() if e.created_at else None,
                "meta": e.meta or {},
            }
        )

    return {"items": items, "limit": limit}
