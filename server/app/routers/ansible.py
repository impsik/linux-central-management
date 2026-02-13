from __future__ import annotations

import asyncio
import json
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..db import get_db
from ..deps import require_ui_user
from ..models import AnsibleRun, AppUser
from ..services.ansible import list_playbooks, redact_extra_vars, run_playbook
from ..services.ansible_runs import create_run, get_run_by_key
from ..services.db_utils import transaction

router = APIRouter(prefix="/ansible", tags=["ansible"])


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

    total = db.execute(select(func.count()).select_from(q.subquery())).scalar_one()
    rows = db.execute(q.limit(limit).offset(offset)).scalars().all()

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
    return list_playbooks()


@router.post("/run")
async def ansible_run(
    payload: AnsibleRunRequest,
    user: AppUser = Depends(require_ui_user),
    db: Session = Depends(get_db),
):
    # Create DB record first (so UI can show it immediately)
    redacted = redact_extra_vars(payload.playbook, payload.extra_vars)
    with transaction(db):
        run = create_run(
            db=db,
            playbook=payload.playbook,
            targets=payload.agent_ids,
            extra_vars_redacted=redacted,
            created_by=getattr(user, "username", None),
        )
        run_id = run.run_key

    try:
        # Resolve selected agent ids to connection targets (prefer IP, then FQDN, then hostname).
        from ..models import Host
        from ..services.hosts import resolve_host_target

        hosts = db.execute(select(Host).where(Host.agent_id.in_(payload.agent_ids))).scalars().all()
        by_id = {h.agent_id: h for h in hosts}
        inventory_hosts: list[str] = []
        for aid in payload.agent_ids:
            h = by_id.get(aid)
            inventory_hosts.append(resolve_host_target(h) if h is not None else aid)

        result = await asyncio.to_thread(
            run_playbook,
            payload.playbook,
            payload.agent_ids,
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
    except HTTPException:
        with transaction(db):
            run = get_run_by_key(db, run_id)
            run.status = "failed"
            run.rc = 1
            run.stderr = "HTTPException"
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
    from ..services.ansible import list_logs

    return list_logs(limit=limit)


@router.get("/logs/{log_name}")
def ansible_log_file(log_name: str, user: AppUser = Depends(require_ui_user)):
    from ..services.ansible import get_log_file

    path = get_log_file(log_name)
    return FileResponse(path=path, filename=Path(path).name, media_type="text/plain")
