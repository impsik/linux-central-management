from __future__ import annotations

import uuid
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import settings
from ..dispatcher import dispatcher
from ..models import Job, JobRun
from .db_utils import transaction


@dataclass(frozen=True)
class CreatedJob:
    job: Job
    job_key: str


def create_job_with_runs(
    *,
    db: Session,
    job_type: str,
    payload: dict,
    agent_ids: list[str],
    created_by: str = "api",
    commit: bool = True,
) -> CreatedJob:
    """Create a Job + JobRun rows (queued) in one place.

    If commit=False, caller must commit/rollback.
    """

    job_key = str(uuid.uuid4())

    def _create() -> Job:
        job = Job(
            job_key=job_key,
            created_by=created_by,
            job_type=job_type,
            payload=payload,
            selector={"agent_ids": agent_ids},
        )
        db.add(job)
        db.flush()  # get job.id

        for aid in agent_ids:
            db.add(JobRun(job_id=job.id, agent_id=aid, job_nonce=secrets.token_urlsafe(32), status="queued"))

        return job

    if commit:
        with transaction(db):
            job = _create()
    else:
        job = _create()

    return CreatedJob(job=job, job_key=job_key)


def ensure_job_run_nonce(run: JobRun) -> str:
    nonce = (getattr(run, "job_nonce", None) or "").strip()
    if not nonce:
        nonce = secrets.token_urlsafe(32)
        run.job_nonce = nonce
    return nonce


def build_agent_job_payload(job: Job, agent_id: str) -> dict:
    """Build the wire payload expected by the Go agent from persisted job data."""

    job_type = str(job.job_type or "").strip()
    payload = job.payload if isinstance(job.payload, dict) else {}
    out: dict = {"job_id": job.job_key, "type": job_type}

    packages = payload.get("packages") or []
    packages_by_agent = payload.get("packages_by_agent") if isinstance(payload.get("packages_by_agent"), dict) else {}
    per_agent_packages = packages_by_agent.get(agent_id) if isinstance(packages_by_agent, dict) else None
    if job_type in {"pkg-upgrade", "pkg-install", "pkg-reinstall", "pkg-remove", "query-pkg-version"}:
        out["packages"] = per_agent_packages or packages or []

    if job_type == "query-pkg-updates":
        out["refresh"] = bool(payload.get("refresh", False))

    if job_type == "query-pkg-info":
        out["package_name"] = payload.get("package_name") or payload.get("name") or ""

    if job_type == "cve-check":
        out["cve"] = payload.get("cve") or payload.get("package_name") or ""

    if job_type in {"service-control", "query-service-details"}:
        out["service_name"] = payload.get("service_name") or payload.get("service") or ""
        if payload.get("action") is not None:
            out["action"] = payload.get("action")

    if job_type == "query-user-details":
        out["service_name"] = payload.get("username") or payload.get("service_name") or ""

    if job_type in {"user-lock", "user-unlock"}:
        out["service_name"] = payload.get("username") or payload.get("service_name") or ""

    if job_type == "firewall-control":
        for key in ("action", "port", "protocol", "source", "service"):
            if payload.get(key) is not None:
                out[key] = payload.get(key)

    if job_type == "disk-cleanup":
        out["dry_run"] = bool(payload.get("dry_run", True))
        out["cleanup_actions"] = payload.get("actions") or payload.get("cleanup_actions") or []

    if job_type == "ssh-key-deploy":
        out["service_name"] = payload.get("username") or payload.get("service_name") or ""
        out["action"] = payload.get("sudo_profile") or payload.get("action") or "B"
        out["package_name"] = payload.get("public_key") or payload.get("package_name") or ""

    return out


def recover_stale_job_runs_for_agent(db: Session, agent_id: str, *, now: datetime | None = None) -> dict:
    """Requeue or fail abandoned running jobs for one agent.

    This is deliberately scoped to the polling agent so the recovery work stays
    cheap and predictable on large fleets.
    """

    stale_after = int(getattr(settings, "job_run_stale_after_seconds", 1800) or 0)
    if stale_after <= 0:
        return {"requeued": 0, "failed": 0}

    max_retries = max(0, int(getattr(settings, "job_run_max_retries", 1) or 0))
    now = now or datetime.now(timezone.utc)
    cutoff = now - timedelta(seconds=stale_after)

    db.flush()

    candidates = (
        db.execute(
            select(JobRun)
            .where(
                JobRun.agent_id == agent_id,
                JobRun.status == "running",
                JobRun.started_at.is_not(None),
            )
            .order_by(JobRun.started_at.asc())
        )
        .scalars()
        .all()
    )

    requeued = 0
    failed = 0
    for run in candidates:
        started_at = run.started_at
        if started_at is None:
            continue
        if started_at.tzinfo is None:
            started_at = started_at.replace(tzinfo=timezone.utc)
        if started_at >= cutoff:
            continue

        retry_count = int(getattr(run, "retry_count", 0) or 0)
        if retry_count < max_retries:
            run.retry_count = retry_count + 1
            # A late event from the abandoned attempt must not finish its retry.
            run.job_nonce = secrets.token_urlsafe(32)
            run.status = "queued"
            run.started_at = None
            run.error = f"requeued after stale running state older than {stale_after}s"
            requeued += 1
        else:
            run.status = "failed"
            run.finished_at = now
            run.error = f"failed after {retry_count} stale running retry attempt(s)"
            failed += 1

    return {"requeued": requeued, "failed": failed}


def job_run_observability(run: JobRun, *, now: datetime | None = None) -> dict:
    now = now or datetime.now(timezone.utc)
    retry_count = int(getattr(run, "retry_count", 0) or 0)
    stale_after = int(getattr(settings, "job_run_stale_after_seconds", 1800) or 0)
    error_text = str(getattr(run, "error", "") or "").strip().lower()
    is_cancelled = bool(run.status == "failed" and error_text.startswith("cancelled"))

    running_seconds = None
    is_stale = False
    if run.status == "running" and run.started_at is not None:
        started_at = run.started_at
        if started_at.tzinfo is None:
            started_at = started_at.replace(tzinfo=timezone.utc)
        running_seconds = max(0, int((now - started_at).total_seconds()))
        is_stale = stale_after > 0 and running_seconds >= stale_after

    return {
        "retry_count": retry_count,
        "running_seconds": running_seconds,
        "stale_after_seconds": stale_after,
        "is_stale": is_stale,
        "is_cancelled": is_cancelled,
    }


def claim_queued_job_for_agent(db: Session, agent_id: str, job_key: str | None = None) -> dict | None:
    """Atomically claim the next queued run for an agent and return agent payload.

    The database is the durable queue. The in-memory dispatcher may still wake a
    long-polling agent, but this claim path decides what actually gets executed.
    """

    now = datetime.now(timezone.utc)

    with transaction(db):
        recover_stale_job_runs_for_agent(db, agent_id, now=now)
        db.flush()

        stmt = (
            select(JobRun, Job)
            .join(Job, Job.id == JobRun.job_id)
            .where(JobRun.agent_id == agent_id, JobRun.status == "queued")
            .order_by(Job.created_at.asc())
            .limit(1)
        )
        if job_key:
            stmt = stmt.where(Job.job_key == job_key)

        try:
            dialect = db.get_bind().dialect.name
        except Exception:
            dialect = ""
        if dialect == "postgresql":
            stmt = stmt.with_for_update(skip_locked=True)

        row = db.execute(stmt).first()
        if not row:
            return None

        run, job = row
        run.status = "running"
        run.started_at = run.started_at or now
        run.finished_at = None
        run.error = None
        payload = build_agent_job_payload(job, agent_id)
        payload["job_nonce"] = ensure_job_run_nonce(run)
        return payload


async def push_job_to_agents(*, agent_ids: list[str], job_payload_builder) -> None:
    """Wake long-polling agents after durable DB job rows are created.

    The dispatcher is intentionally only a wake-up optimization now; queued job
    state lives in the database and is claimed by /agent/next-job.
    """
    for aid in agent_ids:
        await dispatcher.push_job(aid, job_payload_builder(aid))
