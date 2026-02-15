from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..db import get_db
from ..deps import require_ui_user
from ..models import HighRiskActionRequest, Job, JobRun
from ..schemas import JobCreateCVECheck, JobCreateDistUpgrade, JobCreateInventoryNow, JobCreatePkgQuery, JobCreatePkgUpgrade
from ..services.db_utils import transaction
from ..services.audit import log_event
from ..services.high_risk_approval import is_approval_required
from ..services.jobs import create_job_with_runs, push_job_to_agents
from ..services.maintenance import assert_action_allowed_now
from ..services.targets import resolve_agent_ids

router = APIRouter(prefix="/jobs", tags=["jobs"])


@router.get("")
def list_jobs(
    status: str | None = None,
    type: str | None = None,  # noqa: A002
    agent_id: str | None = None,
    created_by: str | None = None,
    limit: int = 50,
    offset: int = 0,
    db: Session = Depends(get_db),
):
    """List jobs with basic filtering + pagination.

    This is intended for a future SPA jobs table.
    """

    if limit < 1:
        limit = 1
    if limit > 200:
        limit = 200
    if offset < 0:
        offset = 0

    status_norm = (status or "").strip().lower() or None
    if status_norm and status_norm not in ("queued", "running", "success", "failed"):
        raise HTTPException(400, "invalid status")

    from ..services.jobs_list import build_jobs_list_query

    q = build_jobs_list_query(
        db=db,
        status=status_norm,  # type: ignore[arg-type]
        job_type=type,
        agent_id=agent_id,
        created_by=created_by,
    )

    # total count (filters apply)
    total = db.execute(select(func.count()).select_from(q.subquery())).scalar_one()

    rows = db.execute(q.limit(limit).offset(offset)).all()

    items = []
    for job, computed_status, runs_total, runs_failed, runs_running, runs_success in rows:
        done = bool(runs_total) and computed_status in ("success", "failed")
        items.append(
            {
                "job_id": job.job_key,
                "type": job.job_type,
                "created_by": job.created_by,
                "created_at": job.created_at,
                "selector": job.selector,
                "status": computed_status,
                "done": done,
                "detail_url": f"/jobs/{job.job_key}",
                "runs": {
                    "total": int(runs_total or 0),
                    "running": int(runs_running or 0),
                    "success": int(runs_success or 0),
                    "failed": int(runs_failed or 0),
                },
            }
        )

    return {"items": items, "total": int(total or 0), "limit": limit, "offset": offset}


@router.post("/pkg-upgrade")
async def create_pkg_upgrade(payload: JobCreatePkgUpgrade, db: Session = Depends(get_db)):
    targets = resolve_agent_ids(db, payload.agent_ids, payload.labels)
    if not targets:
        raise HTTPException(400, "No targets resolved (agent_ids or labels required).")

    packages = payload.packages or []
    packages_by_agent = payload.packages_by_agent or {}

    if not packages and not packages_by_agent:
        raise HTTPException(400, "packages or packages_by_agent is required")

    with transaction(db):
        created = create_job_with_runs(
            db=db,
            job_type="pkg-upgrade",
            payload={
                "packages": packages,
                "packages_by_agent": packages_by_agent,
            },
            agent_ids=targets,
            commit=False,
        )

    async def build(aid: str):
        # Prefer per-agent packages if provided; fall back to global packages.
        pkgs = (packages_by_agent.get(aid) or packages) or []
        return {"job_id": created.job_key, "type": "pkg-upgrade", "packages": pkgs}

    await push_job_to_agents(
        agent_ids=targets,
        job_payload_builder=build,
    )

    return {"job_id": created.job_key, "targets": targets}


@router.post("/pkg-query")
async def create_pkg_query(payload: JobCreatePkgQuery, db: Session = Depends(get_db)):
    targets = resolve_agent_ids(db, payload.agent_ids, payload.labels)
    if not targets:
        raise HTTPException(400, "No targets resolved (agent_ids or labels required).")
    if not payload.packages:
        raise HTTPException(400, "packages is required")

    with transaction(db):
        created = create_job_with_runs(
            db=db,
            job_type="query-pkg-version",
            payload={"packages": payload.packages},
            agent_ids=targets,
            commit=False,
        )

    await push_job_to_agents(
        agent_ids=targets,
        job_payload_builder=lambda aid: {
            "job_id": created.job_key,
            "type": "query-pkg-version",
            "packages": payload.packages,
        },
    )

    return {"job_id": created.job_key, "targets": targets}


@router.post("/inventory-now")
async def inventory_now(payload: JobCreateInventoryNow, db: Session = Depends(get_db)):
    """Trigger immediate inventory refresh on targeted agents."""

    targets = resolve_agent_ids(db, payload.agent_ids, payload.labels)
    if not targets:
        raise HTTPException(400, "No targets resolved (agent_ids or labels required).")

    with transaction(db):
        created = create_job_with_runs(
            db=db,
            job_type="inventory-now",
            payload={},
            agent_ids=targets,
            commit=False,
        )

    await push_job_to_agents(
        agent_ids=targets,
        job_payload_builder=lambda aid: {"job_id": created.job_key, "type": "inventory-now"},
    )

    return {"job_id": created.job_key, "targets": targets}


@router.post("/cve-check")
async def cve_check(payload: JobCreateCVECheck, db: Session = Depends(get_db)):
    """Run an Ubuntu-native CVE inspection (pro fix <CVE> --dry-run) on targeted agents."""

    cve = (payload.cve or "").strip().upper()
    if not cve.startswith("CVE-"):
        raise HTTPException(400, "invalid cve format")

    targets = resolve_agent_ids(db, payload.agent_ids, payload.labels)
    if not targets:
        raise HTTPException(400, "No targets resolved (agent_ids or labels required).")

    with transaction(db):
        created = create_job_with_runs(
            db=db,
            job_type="cve-check",
            payload={"cve": cve},
            agent_ids=targets,
            commit=False,
        )

    await push_job_to_agents(
        agent_ids=targets,
        job_payload_builder=lambda aid: {"job_id": created.job_key, "type": "cve-check", "cve": cve},
    )

    return {"job_id": created.job_key, "targets": targets, "cve": cve}


@router.post("/dist-upgrade")
async def dist_upgrade(payload: JobCreateDistUpgrade, request: Request, db: Session = Depends(get_db), user=Depends(require_ui_user)):
    """Run apt-get dist-upgrade/full-upgrade on targeted agents."""

    try:
        assert_action_allowed_now("dist-upgrade")
    except PermissionError as e:
        raise HTTPException(403, str(e))

    targets = resolve_agent_ids(db, payload.agent_ids, payload.labels)
    if not targets:
        raise HTTPException(400, "No targets resolved (agent_ids or labels required).")

    if is_approval_required("dist-upgrade"):
        with transaction(db):
            req = HighRiskActionRequest(
                user_id=user.id,
                action="dist-upgrade",
                payload={"agent_ids": targets},
                status="pending",
            )
            db.add(req)
            db.flush()
            log_event(
                db,
                action="high_risk.request.created",
                actor=user,
                request=request,
                target_type="high_risk_action_request",
                target_id=str(req.id),
                target_name="dist-upgrade",
                meta={"request_id": str(req.id), "action": "dist-upgrade", "target_count": len(targets)},
            )
        return {
            "approval_required": True,
            "request_id": str(req.id),
            "action": "dist-upgrade",
            "targets": targets,
            "status": "pending",
        }

    with transaction(db):
        created = create_job_with_runs(
            db=db,
            job_type="dist-upgrade",
            payload={},
            agent_ids=targets,
            commit=False,
        )

    await push_job_to_agents(
        agent_ids=targets,
        job_payload_builder=lambda aid: {"job_id": created.job_key, "type": "dist-upgrade"},
    )

    return {"job_id": created.job_key, "targets": targets}


@router.get("/{job_id}")
def job_status(job_id: str, db: Session = Depends(get_db)):
    job = db.execute(select(Job).where(Job.job_key == job_id)).scalar_one_or_none()
    if not job:
        raise HTTPException(404, "unknown job")

    runs = db.execute(select(JobRun).where(JobRun.job_id == job.id)).scalars().all()

    result_data = {}
    if job.job_type in ("query-users", "query-services", "query-pkg-version", "cve-check") and runs:
        run = runs[0]
        if run.status == "success" and run.stdout:
            import json

            try:
                result_data = json.loads(run.stdout)
            except Exception:
                result_data = {}

    done = bool(runs)
    for r in runs:
        if r.status not in ("success", "failed"):
            done = False
            break

    return {
        "job_id": job.job_key,
        "type": job.job_type,
        "payload": job.payload,
        "selector": job.selector,
        "created_at": job.created_at,
        "done": done,
        "runs": [
            {
                "agent_id": r.agent_id,
                "status": r.status,
                "started_at": r.started_at,
                "finished_at": r.finished_at,
                "exit_code": r.exit_code,
                "error": r.error,
                "stdout": r.stdout if job.job_type in ("query-users", "query-services", "query-pkg-version", "cve-check") else None,
            }
            for r in runs
        ],
        "result": result_data if result_data else None,
    }

@router.get("/{job_id}/runs/{agent_id}/stdout.txt")
def download_job_run_stdout(job_id: str, agent_id: str, db: Session = Depends(get_db), user=Depends(require_ui_user)):
    from fastapi.responses import PlainTextResponse

    job = db.execute(select(Job).where(Job.job_key == job_id)).scalar_one_or_none()
    if not job:
        raise HTTPException(404, "unknown job")

    run = db.execute(select(JobRun).where(JobRun.job_id == job.id, JobRun.agent_id == agent_id)).scalar_one_or_none()
    if not run:
        raise HTTPException(404, "unknown job run")

    return PlainTextResponse(run.stdout or "")


@router.get("/{job_id}/runs/{agent_id}/stderr.txt")
def download_job_run_stderr(job_id: str, agent_id: str, db: Session = Depends(get_db), user=Depends(require_ui_user)):
    from fastapi.responses import PlainTextResponse

    job = db.execute(select(Job).where(Job.job_key == job_id)).scalar_one_or_none()
    if not job:
        raise HTTPException(404, "unknown job")

    run = db.execute(select(JobRun).where(JobRun.job_id == job.id, JobRun.agent_id == agent_id)).scalar_one_or_none()
    if not run:
        raise HTTPException(404, "unknown job run")

    return PlainTextResponse(run.stderr or "")


@router.get("/{job_id}/logs.zip")
def download_job_logs(job_id: str, db: Session = Depends(get_db), user=Depends(require_ui_user)):
    """Download job run logs as a zip (stdout/stderr per host)."""

    from fastapi.responses import StreamingResponse
    import io
    import json
    import zipfile

    job = db.execute(select(Job).where(Job.job_key == job_id)).scalar_one_or_none()
    if not job:
        raise HTTPException(404, "unknown job")

    runs = db.execute(select(JobRun).where(JobRun.job_id == job.id)).scalars().all()

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, mode="w", compression=zipfile.ZIP_DEFLATED) as z:
        meta = {
            "job_id": job.job_key,
            "type": job.job_type,
            "created_by": job.created_by,
            "created_at": job.created_at.isoformat() if job.created_at else None,
            "selector": job.selector,
        }
        z.writestr("job.json", json.dumps(meta, indent=2, default=str))

        for r in runs:
            aid = (r.agent_id or "unknown").replace("/", "_")
            rmeta = {
                "agent_id": r.agent_id,
                "status": r.status,
                "started_at": r.started_at.isoformat() if r.started_at else None,
                "finished_at": r.finished_at.isoformat() if r.finished_at else None,
                "exit_code": r.exit_code,
                "error": r.error,
            }
            z.writestr(f"{aid}/meta.json", json.dumps(rmeta, indent=2, default=str))
            z.writestr(f"{aid}/stdout.txt", r.stdout or "")
            z.writestr(f"{aid}/stderr.txt", r.stderr or "")

    buf.seek(0)
    headers = {"Content-Disposition": f'attachment; filename="{job_id}.logs.zip"'}
    return StreamingResponse(buf, media_type="application/zip", headers=headers)
