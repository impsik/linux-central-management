from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from ..db import get_db
from ..deps import require_admin_user, require_ui_user
from ..models import AppUser, HighRiskActionRequest
from ..services.audit import log_event
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
def list_pending(
    db: Session = Depends(get_db),
    admin=Depends(require_admin_user),
    mode: str = Query("pending", pattern="^(pending|recent)$"),
    hours: int = Query(24, ge=1, le=168),
):
    q = select(HighRiskActionRequest, AppUser.username).join(AppUser, AppUser.id == HighRiskActionRequest.user_id)
    if mode == "pending":
        q = q.where(HighRiskActionRequest.status == "pending")
    else:
        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
        q = q.where(HighRiskActionRequest.created_at >= cutoff)

    rows = db.execute(q.order_by(HighRiskActionRequest.created_at.desc()).limit(300)).all()

    items = []
    for r, uname in rows:
        items.append(
            {
                "id": str(r.id),
                "user": uname,
                "action": r.action,
                "payload": r.payload,
                "status": r.status,
                "approved_by": r.approved_by,
                "execution_ref": r.execution_ref,
                "error": r.error,
                "created_at": r.created_at.isoformat() if r.created_at else None,
                "finished_at": r.finished_at.isoformat() if r.finished_at else None,
            }
        )
    return {"items": items, "mode": mode, "hours": hours}


@router.post("/admin/{request_id}/approve")
async def approve_request(request_id: str, request: Request, db: Session = Depends(get_db), admin=Depends(require_admin_user)):
    try:
        req_uuid = UUID(str(request_id))
    except Exception:
        raise HTTPException(400, "invalid request id")

    req = db.execute(select(HighRiskActionRequest).where(HighRiskActionRequest.id == req_uuid)).scalar_one_or_none()
    if not req:
        raise HTTPException(404, "request not found")

    # Two-person rule: requester cannot self-approve.
    if str(getattr(req, "user_id", "")) == str(getattr(admin, "id", "")):
        with transaction(db):
            log_event(
                db,
                action="high_risk.request.approve_denied_self",
                actor=admin,
                request=request,
                target_type="high_risk_action_request",
                target_id=str(req.id),
                target_name=req.action,
                meta={"request_id": str(req.id), "action": req.action},
            )
        raise HTTPException(403, "Two-person rule: requester cannot approve own request")

    if req.status != "pending":
        return {"id": str(req.id), "status": req.status, "execution_ref": req.execution_ref}

    # Race-safe claim: exactly one admin can transition pending -> approved.
    now = datetime.now(timezone.utc)
    with transaction(db):
        claimed = db.execute(
            update(HighRiskActionRequest)
            .where(HighRiskActionRequest.id == req.id, HighRiskActionRequest.status == "pending")
            .values(status="approved", approved_by=getattr(admin, "username", None), approved_at=now)
        ).rowcount or 0
        if claimed:
            log_event(
                db,
                action="high_risk.request.approved",
                actor=admin,
                request=request,
                target_type="high_risk_action_request",
                target_id=str(req.id),
                target_name=req.action,
                meta={"request_id": str(req.id), "action": req.action},
            )

    req = db.execute(select(HighRiskActionRequest).where(HighRiskActionRequest.id == req_uuid)).scalar_one_or_none()
    if not req:
        raise HTTPException(404, "request not found")
    if claimed == 0:
        return {"id": str(req.id), "status": req.status, "execution_ref": req.execution_ref}

    p = req.payload or {}
    action = (req.action or "").strip().lower()

    try:
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
                req.execution_ref = created.job_key

            await push_job_to_agents(
                agent_ids=agent_ids,
                job_payload_builder=lambda aid: {"job_id": created.job_key, "type": "dist-upgrade"},
            )

            with transaction(db):
                req.status = "executed"
                req.finished_at = datetime.now(timezone.utc)
                log_event(
                    db,
                    action="high_risk.request.executed",
                    actor=admin,
                    request=request,
                    target_type="high_risk_action_request",
                    target_id=str(req.id),
                    target_name=req.action,
                    meta={"request_id": str(req.id), "action": req.action, "execution_ref": created.job_key},
                )

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
                req.execution_ref = c.campaign_key
                req.finished_at = datetime.now(timezone.utc)
                log_event(
                    db,
                    action="high_risk.request.executed",
                    actor=admin,
                    request=request,
                    target_type="high_risk_action_request",
                    target_id=str(req.id),
                    target_name=req.action,
                    meta={"request_id": str(req.id), "action": req.action, "execution_ref": c.campaign_key},
                )

            return {"id": str(req.id), "status": req.status, "execution_ref": c.campaign_key}

        raise HTTPException(400, "unsupported action")
    except HTTPException:
        # Keep explicit HTTP errors as-is; also persist failed state for traceability.
        with transaction(db):
            req.status = "failed"
            req.error = "execution failed"
            req.finished_at = datetime.now(timezone.utc)
            log_event(
                db,
                action="high_risk.request.failed",
                actor=admin,
                request=request,
                target_type="high_risk_action_request",
                target_id=str(req.id),
                target_name=req.action,
                meta={"request_id": str(req.id), "action": req.action, "error": req.error},
            )
        raise
    except Exception as e:
        with transaction(db):
            req.status = "failed"
            req.error = str(e)
            req.finished_at = datetime.now(timezone.utc)
            log_event(
                db,
                action="high_risk.request.failed",
                actor=admin,
                request=request,
                target_type="high_risk_action_request",
                target_id=str(req.id),
                target_name=req.action,
                meta={"request_id": str(req.id), "action": req.action, "error": str(e)},
            )
        raise


@router.post("/admin/{request_id}/reject")
def reject_request(
    request_id: str,
    request: Request,
    payload: ApprovalDecision | None = None,
    db: Session = Depends(get_db),
    admin=Depends(require_admin_user),
):
    try:
        req_uuid = UUID(str(request_id))
    except Exception:
        raise HTTPException(400, "invalid request id")

    req = db.execute(select(HighRiskActionRequest).where(HighRiskActionRequest.id == req_uuid)).scalar_one_or_none()
    if not req:
        raise HTTPException(404, "request not found")

    # Two-person rule: requester cannot self-reject.
    if str(getattr(req, "user_id", "")) == str(getattr(admin, "id", "")):
        with transaction(db):
            log_event(
                db,
                action="high_risk.request.reject_denied_self",
                actor=admin,
                request=request,
                target_type="high_risk_action_request",
                target_id=str(req.id),
                target_name=req.action,
                meta={"request_id": str(req.id), "action": req.action},
            )
        raise HTTPException(403, "Two-person rule: requester cannot reject own request")

    if req.status != "pending":
        return {"id": str(req.id), "status": req.status}

    with transaction(db):
        changed = db.execute(
            update(HighRiskActionRequest)
            .where(HighRiskActionRequest.id == req.id, HighRiskActionRequest.status == "pending")
            .values(
                status="rejected",
                approved_by=getattr(admin, "username", None),
                approved_at=datetime.now(timezone.utc),
                error=(payload.note if payload else None) or "rejected by admin",
                finished_at=datetime.now(timezone.utc),
            )
        ).rowcount or 0

        if changed:
            log_event(
                db,
                action="high_risk.request.rejected",
                actor=admin,
                request=request,
                target_type="high_risk_action_request",
                target_id=str(req.id),
                target_name=req.action,
                meta={"request_id": str(req.id), "action": req.action},
            )

    req = db.execute(select(HighRiskActionRequest).where(HighRiskActionRequest.id == req_uuid)).scalar_one_or_none()
    if not req:
        raise HTTPException(404, "request not found")
    return {"id": str(req.id), "status": req.status}
