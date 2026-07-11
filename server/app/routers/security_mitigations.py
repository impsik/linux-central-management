from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ..db import get_db
from ..deps import require_ui_user
from ..services.audit import log_event
from ..services.db_utils import transaction
from ..services.jobs import create_job_with_runs, push_job_to_agents
from ..services.rbac import permissions_for
from ..services.security_mitigations import get_mitigation, mitigation_catalog
from ..services.targets import resolve_agent_ids

router = APIRouter(prefix="/security/mitigations", tags=["security-mitigations"])


class MitigationAssessmentRequest(BaseModel):
    agent_ids: list[str] = Field(default_factory=list)
    labels: dict[str, str] | None = None


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
