from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..db import get_db
from ..deps import require_ui_user
from ..services.db_utils import transaction
from ..services.host_router_utils import get_visible_host_or_404, require_host_control_permission, require_permission
from ..services.hosts import is_host_online, seconds_since_seen
from ..services.host_job_dispatch import (
    dispatch_host_job,
    parse_json_run_stdout,
    push_dispatched_host_job,
    require_successful_run,
    wait_for_host_job_or_504,
)

router = APIRouter(prefix="/hosts", tags=["hosts"])


@router.get("/{agent_id}/services")
async def get_services(agent_id: str, wait: bool = True, db: Session = Depends(get_db), user=Depends(require_ui_user)):
    host = get_visible_host_or_404(db, user, agent_id)

    if not is_host_online(host):
        t = seconds_since_seen(host)
        if t is not None:
            raise HTTPException(503, f"Agent appears offline (last seen {int(t)}s ago)")
        raise HTTPException(503, "Agent appears offline")

    created, job_id, push_kwargs = dispatch_host_job(
        db=db,
        agent_id=agent_id,
        job_type="query-services",
        payload={},
    )

    await push_dispatched_host_job(push_kwargs=push_kwargs)

    if not wait:
        return {"job_id": created.job_key, "status": "queued", "message": "Job queued, poll /jobs/{job_id} for results"}

    timeout = 20
    run = await wait_for_host_job_or_504(
        job_id=job_id,
        agent_id=agent_id,
        timeout_s=timeout,
        timeout_message=f"Timeout waiting for services query after {timeout}s",
    )
    require_successful_run(run, error_message="Services query failed")
    return parse_json_run_stdout(run, {})


@router.post("/{agent_id}/services/{service_name}/{action}")
async def control_service(
    agent_id: str,
    service_name: str,
    action: str,
    wait: bool = True,
    db: Session = Depends(get_db),
    user=Depends(require_ui_user),
):
    host = get_visible_host_or_404(db, user, agent_id)
    require_host_control_permission(user, host, "can_manage_services", "Insufficient permissions to manage services")

    if not is_host_online(host):
        t = seconds_since_seen(host)
        if t is not None:
            raise HTTPException(503, f"Agent appears offline (last seen {int(t)}s ago)")
        raise HTTPException(503, "Agent appears offline")

    action_norm = (action or "").strip().lower()
    if action_norm not in ("start", "stop", "restart", "enable", "disable"):
        raise HTTPException(400, "action must be one of: start, stop, restart, enable, disable")

    created, job_id, push_kwargs = dispatch_host_job(
        db=db,
        agent_id=agent_id,
        job_type="service-control",
        payload={"service_name": service_name, "action": action_norm},
    )

    await push_dispatched_host_job(push_kwargs=push_kwargs)

    if not wait:
        return {"job_id": created.job_key, "status": "queued"}

    timeout = 30
    run = await wait_for_host_job_or_504(
        job_id=job_id,
        agent_id=agent_id,
        timeout_s=timeout,
        timeout_message=f"Timeout waiting for service {action_norm} after {timeout}s",
    )
    require_successful_run(run, error_message=f"Service {action_norm} failed", include_stdout=True)
    return {"job_id": created.job_key, "status": "success"}


@router.get("/{agent_id}/services/{service_name}")
async def get_service_details(agent_id: str, service_name: str, wait: bool = True, db: Session = Depends(get_db), user=Depends(require_ui_user)):
    """Return selected systemd properties for a service."""
    host = get_visible_host_or_404(db, user, agent_id)

    if not is_host_online(host):
        t = seconds_since_seen(host)
        if t is not None:
            raise HTTPException(503, f"Agent appears offline (last seen {int(t)}s ago)")
        raise HTTPException(503, "Agent appears offline")

    created, job_id, push_kwargs = dispatch_host_job(
        db=db,
        agent_id=agent_id,
        job_type="query-service-details",
        payload={"service_name": service_name},
    )

    await push_dispatched_host_job(push_kwargs=push_kwargs)

    if not wait:
        return {"job_id": created.job_key, "status": "queued"}

    timeout = 12
    run = await wait_for_host_job_or_504(
        job_id=job_id,
        agent_id=agent_id,
        timeout_s=timeout,
        timeout_message=f"Timeout waiting for service details after {timeout}s",
    )
    require_successful_run(run, error_message="Service details query failed", include_stdout=True)
    return {"service": parse_json_run_stdout(run, {})}
