from __future__ import annotations

import json

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import get_db
from ..deps import require_ui_user
from ..services.audit import log_event
from ..services.db_utils import transaction
from ..models import HighRiskActionRequest, Job, JobRun
from ..services.jobs import create_job_with_runs, push_job_to_agents
from ..services.rbac import permissions_for
from ..services.security_mitigations import get_mitigation, mitigation_catalog
from ..services.targets import resolve_agent_ids

router = APIRouter(prefix="/security/mitigations", tags=["security-mitigations"])


class MitigationAssessmentRequest(BaseModel):
    agent_ids: list[str] = Field(default_factory=list)
    labels: dict[str, str] | None = None


class MitigationApplyRequest(MitigationAssessmentRequest):
    assessment_job_id: str = Field(min_length=1, max_length=160)


@router.get("")
def list_mitigations(user=Depends(require_ui_user)):
    permissions_for(user)
    return {"items": mitigation_catalog()}


@router.post("/{mitigation_id}/assess")
async def assess_mitigation(
    mitigation_id: str,
    payload: MitigationAssessmentRequest,
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(require_ui_user),
):
    perms = permissions_for(user)
    if not perms.get("can_manage_packages"):
        raise HTTPException(403, "Insufficient permissions to assess security mitigations")

    mitigation = get_mitigation(mitigation_id)
    if not mitigation:
        raise HTTPException(404, "Unknown security mitigation")

    targets = resolve_agent_ids(db, payload.agent_ids, payload.labels, user=user)
    if not targets:
        raise HTTPException(400, "Select at least one host within your scope")

    job_payload = {
        "mitigation_id": mitigation["id"],
        "mitigation_version": mitigation["version"],
        "action": "assess",
    }
    with transaction(db):
        created = create_job_with_runs(
            db=db,
            job_type="security-mitigation",
            payload=job_payload,
            agent_ids=targets,
            created_by=str(getattr(user, "username", None) or "ui"),
            commit=False,
        )
        log_event(
            db,
            action="security.mitigation.assessment.queued",
            actor=user,
            request=request,
            target_type="security_mitigation",
            target_id=mitigation["id"],
            target_name=mitigation["name"],
            meta={
                "mitigation_version": mitigation["version"],
                "target_count": len(targets),
                "agent_ids": targets,
                "mode": "ASSESS",
            },
        )

    await push_job_to_agents(
        agent_ids=targets,
        job_payload_builder=lambda aid: {
            "job_id": created.job_key,
            "type": "security-mitigation",
            **job_payload,
        },
    )
    return {
        "job_id": created.job_key,
        "mitigation_id": mitigation["id"],
        "mitigation_version": mitigation["version"],
        "action": "assess",
        "targets": targets,
    }


@router.post("/{mitigation_id}/apply")
def request_mitigation_apply(
    mitigation_id: str,
    payload: MitigationApplyRequest,
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(require_ui_user),
):
    perms = permissions_for(user)
    if not perms.get("can_manage_packages"):
        raise HTTPException(403, "Insufficient permissions to apply security mitigations")

    mitigation = get_mitigation(mitigation_id)
    if not mitigation:
        raise HTTPException(404, "Unknown security mitigation")
    if not mitigation.get("apply_available"):
        raise HTTPException(400, "This mitigation does not support automated remediation")

    targets = resolve_agent_ids(db, payload.agent_ids, payload.labels, user=user)
    if not targets:
        raise HTTPException(400, "Select at least one host within your scope")

    assessment = db.execute(select(Job).where(Job.job_key == payload.assessment_job_id)).scalar_one_or_none()
    assessment_payload = assessment.payload if assessment and isinstance(assessment.payload, dict) else {}
    if (
        not assessment
        or assessment.job_type != "security-mitigation"
        or assessment_payload.get("action") != "assess"
        or assessment_payload.get("mitigation_id") != mitigation["id"]
        or int(assessment_payload.get("mitigation_version") or 0) != int(mitigation["version"])
    ):
        raise HTTPException(400, "A matching completed assessment is required before apply")
    runs = db.execute(select(JobRun).where(JobRun.job_id == assessment.id, JobRun.agent_id.in_(targets))).scalars().all()
    vulnerable = set()
    for run in runs:
        try:
            result = json.loads(run.stdout or "{}") if run.status == "success" else {}
        except (TypeError, ValueError):
            result = {}
        if result.get("status") == "vulnerable":
            vulnerable.add(run.agent_id)
    if vulnerable != set(targets):
        raise HTTPException(400, "Apply targets must all be vulnerable in the referenced completed assessment")

    with transaction(db):
        approval = HighRiskActionRequest(
            user_id=user.id,
            action="security-mitigation-apply",
            payload={
                "mitigation_id": mitigation["id"],
                "mitigation_version": mitigation["version"],
                "agent_ids": targets,
                "assessment_job_id": payload.assessment_job_id,
            },
            status="pending",
        )
        db.add(approval)
        db.flush()
        log_event(
            db,
            action="security.mitigation.apply.requested",
            actor=user,
            request=request,
            target_type="high_risk_action_request",
            target_id=str(approval.id),
            target_name=mitigation["name"],
            meta={
                "request_id": str(approval.id),
                "mitigation_id": mitigation["id"],
                "mitigation_version": mitigation["version"],
                "assessment_job_id": payload.assessment_job_id,
                "target_count": len(targets),
                "agent_ids": targets,
            },
        )
    return {
        "approval_required": True,
        "request_id": str(approval.id),
        "action": "security-mitigation-apply",
        "status": "pending",
        "targets": targets,
    }
