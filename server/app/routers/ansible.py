from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..db import get_db
from ..deps import require_ui_user
from ..models import AnsibleRun, AppUser, Host
from ..services.ansible import list_playbooks, redact_extra_vars, run_playbook
from ..services.ansible_runs import create_run, get_run_by_key
from ..services.db_utils import transaction
from ..services.hosts import resolve_host_target
from ..services.rbac import permissions_for
from ..services.user_scopes import filter_agent_ids_for_user

router = APIRouter(prefix="/ansible", tags=["ansible"])


def _require_ansible_access(user: AppUser) -> None:
    if not permissions_for(user).get("can_run_ansible"):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Insufficient permissions to run Ansible")


def _is_admin(user: AppUser) -> bool:
    return (permissions_for(user).get("role") or "").lower() == "admin"


def _normalize_agent_ids(agent_ids: list[str] | None) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for raw in agent_ids or []:
        aid = str(raw or "").strip()
        if aid and aid not in seen:
            seen.add(aid)
            out.append(aid)
    return out


def _visible_ansible_targets(db: Session, user: AppUser, agent_ids: list[str]) -> list[str]:
    targets = _normalize_agent_ids(agent_ids)
    if not targets:
        raise HTTPException(400, "agent_ids is required")

    known = set(db.execute(select(Host.agent_id).where(Host.agent_id.in_(targets))).scalars().all())
    missing = [aid for aid in targets if aid not in known]
    if missing:
        raise HTTPException(404, "Unknown Ansible target")

    if _is_admin(user):
        return targets

    visible = set(filter_agent_ids_for_user(db, user, targets))
    if visible != set(targets):
        raise HTTPException(404, "Unknown Ansible target")
    return targets


def _can_view_ansible_run(db: Session, user: AppUser, run: AnsibleRun) -> bool:
    if _is_admin(user):
        return True
    targets = _normalize_agent_ids(run.targets or [])
    if not targets:
        return False
    visible = set(filter_agent_ids_for_user(db, user, targets))
    return visible == set(targets)


def _require_can_view_ansible_run(db: Session, user: AppUser, run: AnsibleRun) -> None:
    _require_ansible_access(user)
    if not _can_view_ansible_run(db, user, run):
        raise HTTPException(404, "Ansible run not found")


@router.get("/runs")
def list_ansible_runs(
    status: str | None = None,
    playbook: str | None = None,
    created_by: str | None = None,
    limit: int = 50,
    offset: int = 0,
    user: AppUser = Depends(require_ui_user),
    db: Session = Depends(get_db),
):
    _require_ansible_access(user)

    if limit < 1:
        limit = 1
    if limit > 200:
        limit = 200
    if offset < 0:
        offset = 0

    status_norm = (status or "").strip().lower() or None
    if status_norm and status_norm not in ("running", "success", "failed"):
        raise HTTPException(400, "invalid status")

    q = select(AnsibleRun).order_by(AnsibleRun.created_at.desc())
    if status_norm:
        q = q.where(AnsibleRun.status == status_norm)
    if playbook:
        q = q.where(AnsibleRun.playbook == playbook)
    if created_by:
        q = q.where(AnsibleRun.created_by == created_by)

    if _is_admin(user):
        total = db.execute(select(func.count()).select_from(q.subquery())).scalar_one()
        rows = db.execute(q.limit(limit).offset(offset)).scalars().all()
    else:
        all_rows = db.execute(q).scalars().all()
        visible_rows = [r for r in all_rows if _can_view_ansible_run(db, user, r)]
        total = len(visible_rows)
        rows = visible_rows[offset: offset + limit]

    items = [
        {
            "run_id": r.run_key,
            "playbook": r.playbook,
            "created_by": r.created_by,
            "targets": r.targets,
            "status": r.status,
            "done": r.status in ("success", "failed"),
            "rc": r.rc,
            "created_at": r.created_at,
            "finished_at": r.finished_at,
            "log_name": r.log_name,
            "log_url": f"/ansible/runs/{r.run_key}/log" if r.log_name else None,
        }
        for r in rows
    ]

    return {"items": items, "total": int(total or 0), "limit": limit, "offset": offset}


@router.get("/runs/{run_id}")
def get_ansible_run(run_id: str, user: AppUser = Depends(require_ui_user), db: Session = Depends(get_db)):
    r = get_run_by_key(db, run_id)
    _require_can_view_ansible_run(db, user, r)
    return {
        "run_id": r.run_key,
        "playbook": r.playbook,
        "created_by": r.created_by,
        "targets": r.targets,
        "extra_vars": r.extra_vars,
        "status": r.status,
        "done": r.status in ("success", "failed"),
        "rc": r.rc,
        "stdout": r.stdout,
        "stderr": r.stderr,
        "log_name": r.log_name,
        "log_path": r.log_path,
        "log_url": f"/ansible/runs/{r.run_key}/log" if r.log_name else None,
        "created_at": r.created_at,
        "finished_at": r.finished_at,
    }


@router.get("/runs/{run_id}/log")
def get_ansible_run_log(run_id: str, user: AppUser = Depends(require_ui_user), db: Session = Depends(get_db)):
    """Download the stored log artifact for a run (if present)."""
    r = get_run_by_key(db, run_id)
    _require_can_view_ansible_run(db, user, r)
    if not r.log_name:
        raise HTTPException(404, "log not available")

    from ..services.ansible import get_log_file

    path = get_log_file(r.log_name)
    return FileResponse(path=path, filename=Path(path).name, media_type="text/plain")


class AnsibleRunRequest(BaseModel):
    playbook: str
    agent_ids: list[str]
    extra_vars: dict[str, Any] | None = None


@router.get("/playbooks")
def ansible_playbooks(user: AppUser = Depends(require_ui_user)):
    _require_ansible_access(user)
    return list_playbooks()


@router.post("/run")
async def ansible_run(
    payload: AnsibleRunRequest,
    user: AppUser = Depends(require_ui_user),
    db: Session = Depends(get_db),
):
    _require_ansible_access(user)
    targets = _visible_ansible_targets(db, user, payload.agent_ids)

    # Create DB record first (so UI can show it immediately)
    redacted = redact_extra_vars(payload.playbook, payload.extra_vars)
    with transaction(db):
        run = create_run(
            db=db,
            playbook=payload.playbook,
            targets=targets,
            extra_vars_redacted=redacted,
            created_by=getattr(user, "username", None),
        )
        run_id = run.run_key

    try:
        # Resolve selected agent ids to connection targets (prefer IP, then FQDN, then hostname).
        hosts = db.execute(select(Host).where(Host.agent_id.in_(targets))).scalars().all()
        by_id = {h.agent_id: h for h in hosts}
        inventory_hosts: list[str] = []
        for aid in targets:
            h = by_id.get(aid)
            inventory_hosts.append(resolve_host_target(h))

        result = await asyncio.to_thread(
            run_playbook,
            payload.playbook,
            targets,
            payload.extra_vars,
            inventory_hosts=inventory_hosts,
        )
        from ..config import settings
        from ..services.text_utils import truncate

        with transaction(db):
            run = get_run_by_key(db, run_id)
            run.status = "success" if result.get("ok") else "failed"
            run.rc = result.get("rc")
            run.stdout = truncate(result.get("stdout"), int(getattr(settings, "ansible_store_output_max_chars", 20000)))
            run.stderr = truncate(result.get("stderr"), int(getattr(settings, "ansible_store_output_max_chars", 20000)))
            run.log_name = result.get("log_name")
            run.log_path = result.get("log_path")
            run.finished_at = datetime.now(timezone.utc)
        return {"run_id": run_id, **result}
    except HTTPException as e:
        detail = getattr(e, "detail", None)
        detail_text = str(detail) if detail is not None else "HTTPException"
        with transaction(db):
            run = get_run_by_key(db, run_id)
            run.status = "failed"
            run.rc = 1
            run.stderr = detail_text
            run.finished_at = datetime.now(timezone.utc)
        raise
    except Exception as e:
        with transaction(db):
            run = get_run_by_key(db, run_id)
            run.status = "failed"
            run.rc = 1
            run.stderr = str(e)
            run.finished_at = datetime.now(timezone.utc)
        return JSONResponse(status_code=500, content={"run_id": run_id, "ok": False, "rc": 1, "stderr": str(e)})


@router.get("/logs")
def ansible_log_list(limit: int = 50, user: AppUser = Depends(require_ui_user)):
    _require_ansible_access(user)
    if not _is_admin(user):
        raise HTTPException(403, "Admin privileges required")
    from ..services.ansible import list_logs

    return list_logs(limit=limit)


@router.get("/logs/{log_name}")
def ansible_log_file(log_name: str, user: AppUser = Depends(require_ui_user)):
    _require_ansible_access(user)
    if not _is_admin(user):
        raise HTTPException(403, "Admin privileges required")
    from ..services.ansible import get_log_file

    path = get_log_file(log_name)
    return FileResponse(path=path, filename=Path(path).name, media_type="text/plain")
