from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import get_db
from ..deps import require_admin_user, require_ui_user
from ..models import AppUser, HighRiskActionRequest
from ..services.db_utils import transaction
from ..services.jobs import create_job_with_runs, push_job_to_agents
from ..services.patching import create_patch_campaign

router = APIRouter(prefix="/approvals", tags=["approvals"])


class ApprovalDecision(BaseModel):
    note: str | None = None


@router.get("/my")
def list_my_requests(db: Session = Depends(get_db), user=Depends(require_ui_user)):
    rows = (
        db.execute(
            select(HighRiskActionRequest)
            .where(HighRiskActionRequest.user_id == user.id)
            .order_by(HighRiskActionRequest.created_at.desc())
            .limit(200)
        )
        .scalars()
        .all()
    )
    return {
        "items": [
            {
                "id": str(r.id),
                "action": r.action,
                "status": r.status,
                "approved_by": r.approved_by,
                "execution_ref": r.execution_ref,
                "error": r.error,
                "created_at": r.created_at.isoformat() if r.created_at else None,
                "finished_at": r.finished_at.isoformat() if r.finished_at else None,
            }
            for r in rows
        ]
    }


@router.get("/admin/pending")
def list_pending(db: Session = Depends(get_db), admin=Depends(require_admin_user)):
    rows = (
        db.execute(
            select(HighRiskActionRequest, AppUser.username)
            .join(AppUser, AppUser.id == HighRiskActionRequest.user_id)
            .where(HighRiskActionRequest.status == "pending")
            .order_by(HighRiskActionRequest.created_at.asc())
            .limit(200)
        )
        .all()
    )

    items = []
    for r, uname in rows:
        items.append(
            {
                "id": str(r.id),
                "user": uname,
                "action": r.action,
                "payload": r.payload,
                "status": r.status,
                "created_at": r.created_at.isoformat() if r.created_at else None,
            }
        )
    return {"items": items}


@router.post("/admin/{request_id}/approve")
async def approve_request(request_id: str, db: Session = Depends(get_db), admin=Depends(require_admin_user)):
    req = db.execute(select(HighRiskActionRequest).where(HighRiskActionRequest.id == request_id)).scalar_one_or_none()
    if not req:
        raise HTTPException(404, "request not found")
    if req.status != "pending":
        return {"id": str(req.id), "status": req.status, "execution_ref": req.execution_ref}

    p = req.payload or {}
    action = (req.action or "").strip().lower()

    if action == "dist-upgrade":
        agent_ids = [str(x) for x in (p.get("agent_ids") or []) if str(x).strip()]
        if not agent_ids:
            raise HTTPException(400, "request has no targets")
        with transaction(db):
            created = create_job_with_runs(
                db=db,
                job_type="dist-upgrade",
                payload={},
                agent_ids=agent_ids,
                created_by=getattr(admin, "username", None) or "admin",
                commit=False,
            )
            req.status = "approved"
            req.approved_by = getattr(admin, "username", None)
            req.approved_at = datetime.now(timezone.utc)
            req.execution_ref = created.job_key

        await push_job_to_agents(
            agent_ids=agent_ids,
            job_payload_builder=lambda aid: {"job_id": created.job_key, "type": "dist-upgrade"},
        )

        with transaction(db):
            req.status = "executed"
            req.finished_at = datetime.now(timezone.utc)

        return {"id": str(req.id), "status": req.status, "execution_ref": created.job_key}

    if action == "security-campaign":
        with transaction(db):
            c = create_patch_campaign(
                db=db,
                created_by=getattr(admin, "username", None) or "admin",
                kind="security-updates",
                labels=p.get("labels"),
                agent_ids=p.get("agent_ids"),
                rings=p.get("rings"),
                window_start=datetime.fromisoformat(str(p.get("window_start")).replace("Z", "+00:00")),
                window_end=datetime.fromisoformat(str(p.get("window_end")).replace("Z", "+00:00")),
                concurrency=int(p.get("concurrency") or 5),
                reboot_if_needed=bool(p.get("reboot_if_needed") or False),
                include_kernel=bool(p.get("include_kernel") or False),
            )
            req.status = "executed"
            req.approved_by = getattr(admin, "username", None)
            req.approved_at = datetime.now(timezone.utc)
            req.execution_ref = c.campaign_key
            req.finished_at = datetime.now(timezone.utc)

        return {"id": str(req.id), "status": req.status, "execution_ref": c.campaign_key}

    raise HTTPException(400, "unsupported action")


@router.post("/admin/{request_id}/reject")
def reject_request(request_id: str, payload: ApprovalDecision | None = None, db: Session = Depends(get_db), admin=Depends(require_admin_user)):
    req = db.execute(select(HighRiskActionRequest).where(HighRiskActionRequest.id == request_id)).scalar_one_or_none()
    if not req:
        raise HTTPException(404, "request not found")
    if req.status != "pending":
        return {"id": str(req.id), "status": req.status}

    with transaction(db):
        req.status = "rejected"
        req.approved_by = getattr(admin, "username", None)
        req.approved_at = datetime.now(timezone.utc)
        req.error = (payload.note if payload else None) or "rejected by admin"
        req.finished_at = datetime.now(timezone.utc)

    return {"id": str(req.id), "status": req.status}
