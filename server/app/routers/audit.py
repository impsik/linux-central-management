from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from ..db import get_db
from ..deps import require_ui_user
from ..models import AuditEvent, AppUser, OIDCAuthEvent
from ..services.rbac import permissions_for

router = APIRouter(prefix="/audit", tags=["audit"])


def _infer_result(action: str | None, meta: dict | None) -> str:
    a = str(action or "").lower()
    m = meta if isinstance(meta, dict) else {}
    if any(k in m for k in ("error", "error_code", "error_message")):
        return "failed"
    if "failed" in a or "error" in a or "deny" in a or "reject" in a:
        return "failed"
    return "success"


def _normalize_audit_event(e: AuditEvent) -> dict:
    meta = e.meta if isinstance(e.meta, dict) else {}
    return {
        "source": "audit_events",
        "id": str(e.id),
        "timestamp": e.created_at.isoformat() if e.created_at else None,
        "action": e.action,
        "result": _infer_result(e.action, meta),
        "actor": {
            "user_id": str(e.actor_user_id) if getattr(e, "actor_user_id", None) else None,
            "username": e.actor_username,
            "role": e.actor_role,
        },
        "target": {
            "type": e.target_type,
            "id": e.target_id,
            "name": e.target_name,
        },
        "metadata": meta,
    }


def _normalize_oidc_event(e: OIDCAuthEvent) -> dict:
    meta = e.meta if isinstance(e.meta, dict) else {}
    result = "failed" if (e.status or "") == "error" else "success"
    return {
        "source": "oidc_auth_events",
        "id": str(e.id),
        "timestamp": e.created_at.isoformat() if e.created_at else None,
        "action": f"oidc.{e.stage}",
        "result": result,
        "actor": {
            "user_id": None,
            "username": e.username,
            "role": None,
        },
        "target": {
            "type": "auth",
            "id": e.correlation_id,
            "name": e.provider,
        },
        "metadata": {
            "status": e.status,
            "error_code": e.error_code,
            "error_message": e.error_message,
            "email": e.email,
            "subject": e.subject,
            **meta,
        },
    }


@router.get("/timeline")
def list_timeline(
    request: Request,
    action: str | None = None,
    actor: str | None = None,
    result: str | None = None,
    target_type: str | None = None,
    query: str | None = None,
    limit: int = 200,
    offset: int = 0,
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
    if offset < 0:
        offset = 0

    q = select(AuditEvent).order_by(AuditEvent.created_at.desc())
    if action:
        q = q.where(AuditEvent.action == action)
    if actor:
        q = q.where(AuditEvent.actor_username == actor)
    if target_type:
        q = q.where(AuditEvent.target_type == target_type)

    if query:
        pat = f"%{query}%"
        q = q.where(
            or_(
                AuditEvent.action.ilike(pat),
                AuditEvent.actor_username.ilike(pat),
                AuditEvent.target_name.ilike(pat),
            )
        )

    rows = db.execute(q.limit(limit + offset)).scalars().all()
    out = [_normalize_audit_event(r) for r in rows]

    # Include OIDC auth stream in timeline too (lightweight append, then sort)
    oq = select(OIDCAuthEvent).order_by(OIDCAuthEvent.created_at.desc()).limit(limit + offset)
    if query:
        pat = f"%{query}%"
        oq = oq.where(or_(OIDCAuthEvent.stage.ilike(pat), OIDCAuthEvent.error_code.ilike(pat), OIDCAuthEvent.username.ilike(pat)))
    if result:
        if result == "failed":
            oq = oq.where(OIDCAuthEvent.status == "error")
        elif result == "success":
            oq = oq.where(OIDCAuthEvent.status == "success")

    out.extend([_normalize_oidc_event(r) for r in db.execute(oq).scalars().all()])

    if result:
        rr = result.lower().strip()
        out = [it for it in out if str(it.get("result") or "").lower() == rr]

    out.sort(key=lambda it: it.get("timestamp") or "", reverse=True)
    total = len(out)
    items = out[offset : offset + limit]

    return {"items": items, "total": total, "limit": limit, "offset": offset}


@router.get("/{event_id}")
def get_audit_event(
    event_id: str,
    db: Session = Depends(get_db),
    user: AppUser = Depends(require_ui_user),
):
    perms = permissions_for(user)
    if (perms.get("role") or "operator") != "admin":
        raise HTTPException(403, "Admin privileges required")

    e = db.execute(select(AuditEvent).where(AuditEvent.id == event_id)).scalar_one_or_none()
    if not e:
        raise HTTPException(404, "not found")

    return {
        "id": str(e.id),
        "action": e.action,
        "actor": e.actor_username,
        "role": e.actor_role,
        "ip": e.ip_address,
        "user_agent": e.user_agent,
        "target_type": e.target_type,
        "target_id": e.target_id,
        "target_name": e.target_name,
        "created_at": e.created_at.isoformat() if e.created_at else None,
        "meta": e.meta or {},
    }


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
