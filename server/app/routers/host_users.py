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


@router.get("/{agent_id}/users")
async def get_users(agent_id: str, wait: bool = True, db: Session = Depends(get_db), user=Depends(require_ui_user)):
    host = get_visible_host_or_404(db, user, agent_id)

    if not is_host_online(host):
        t = seconds_since_seen(host)
        if t is not None:
            raise HTTPException(503, f"Agent appears offline (last seen {int(t)}s ago)")
        raise HTTPException(503, "Agent appears offline")

    created, job_id, push_kwargs = dispatch_host_job(
        db=db,
        agent_id=agent_id,
        job_type="query-users",
        payload={},
    )

    await push_dispatched_host_job(push_kwargs=push_kwargs)

    if not wait:
        return {"job_id": created.job_key, "status": "queued", "message": "Job queued, poll /jobs/{job_id} for results"}

    timeout = 15
    run = await wait_for_host_job_or_504(
        job_id=job_id,
        agent_id=agent_id,
        timeout_s=timeout,
        timeout_message=f"Timeout waiting for user query after {timeout}s",
    )
    require_successful_run(run, error_message="User query failed")
    return parse_json_run_stdout(run, {})


@router.post("/{agent_id}/users/{username}/{action}")
async def control_user(
    agent_id: str,
    username: str,
    action: str,
    wait: bool = True,
    db: Session = Depends(get_db),
    user=Depends(require_ui_user),
):
    action_norm = (action or "").strip().lower()
    if action_norm not in ("lock", "unlock"):
        raise HTTPException(400, "Invalid action. Must be lock or unlock.")
    username = (username or "").strip()
    if not username:
        raise HTTPException(400, "username is required")
    if username == "root":
        raise HTTPException(400, "Cannot lock root account")

    host = get_visible_host_or_404(db, user, agent_id)
    require_host_control_permission(user, host, "can_lock_users", "Insufficient permissions to lock or unlock users")

    if not is_host_online(host):
        t = seconds_since_seen(host)
        if t is not None:
            raise HTTPException(503, f"Agent appears offline (last seen {int(t)}s ago)")
        raise HTTPException(503, "Agent appears offline")

    job_type = "user-lock" if action_norm == "lock" else "user-unlock"

    created, job_id, push_kwargs = dispatch_host_job(
        db=db,
        agent_id=agent_id,
        job_type=job_type,
        payload={"username": username, "action": action_norm},
        job_payload_builder=lambda aid: {
            "job_id": created.job_key,
            "type": job_type,
            "service_name": username,
        },
    )

    await push_dispatched_host_job(push_kwargs=push_kwargs)

    if not wait:
        return {"job_id": created.job_key, "status": "queued"}

    timeout = 20
    run = await wait_for_host_job_or_504(
        job_id=job_id,
        agent_id=agent_id,
        timeout_s=timeout,
        timeout_message=f"Timeout waiting for user {action_norm} after {timeout}s",
    )
    require_successful_run(run, error_message=f"User {action_norm} failed")
    return {"job_id": created.job_key, "status": "success"}


@router.get("/{agent_id}/users/{username}")
async def get_user_details(agent_id: str, username: str, wait: bool = True, db: Session = Depends(get_db), user=Depends(require_ui_user)):
    """Return detailed info about a system user (best-effort)."""
    host = get_visible_host_or_404(db, user, agent_id)

    if not is_host_online(host):
        t = seconds_since_seen(host)
        if t is not None:
            raise HTTPException(503, f"Agent appears offline (last seen {int(t)}s ago)")
        raise HTTPException(503, "Agent appears offline")

    created, job_id, push_kwargs = dispatch_host_job(
        db=db,
        agent_id=agent_id,
        job_type="query-user-details",
        payload={"username": username},
        job_payload_builder=lambda aid: {
            "job_id": created.job_key,
            "type": "query-user-details",
            "service_name": username,
        },
    )

    await push_dispatched_host_job(push_kwargs=push_kwargs)

    if not wait:
        return {"job_id": created.job_key, "status": "queued"}

    timeout = 12
    run = await wait_for_host_job_or_504(
        job_id=job_id,
        agent_id=agent_id,
        timeout_s=timeout,
        timeout_message=f"Timeout waiting for user details after {timeout}s",
    )
    require_successful_run(run, error_message="User details query failed", include_stdout=True)
    return {"user": parse_json_run_stdout(run, {})}
