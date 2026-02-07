from __future__ import annotations

from datetime import datetime
from typing import Literal

from sqlalchemy import case, exists, func, select
from sqlalchemy.orm import Session

from ..models import Job, JobRun

JobStatus = Literal["queued", "running", "success", "failed"]


def build_jobs_list_query(
    *,
    db: Session,
    status: JobStatus | None = None,
    job_type: str | None = None,
    agent_id: str | None = None,
    created_by: str | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
):
    # Aggregate job run statuses
    agg = (
        select(
            JobRun.job_id.label("job_id"),
            func.count(JobRun.id).label("runs_total"),
            func.sum(case((JobRun.status == "failed", 1), else_=0)).label("runs_failed"),
            func.sum(case((JobRun.status == "running", 1), else_=0)).label("runs_running"),
            func.sum(case((JobRun.status == "success", 1), else_=0)).label("runs_success"),
        )
        .group_by(JobRun.job_id)
        .subquery()
    )

    computed_status = case(
        (agg.c.runs_failed > 0, "failed"),
        (agg.c.runs_running > 0, "running"),
        (agg.c.runs_success == agg.c.runs_total, "success"),
        else_="queued",
    ).label("status")

    q = (
        select(
            Job,
            computed_status,
            func.coalesce(agg.c.runs_total, 0).label("runs_total"),
            func.coalesce(agg.c.runs_failed, 0).label("runs_failed"),
            func.coalesce(agg.c.runs_running, 0).label("runs_running"),
            func.coalesce(agg.c.runs_success, 0).label("runs_success"),
        )
        .outerjoin(agg, agg.c.job_id == Job.id)
        .order_by(Job.created_at.desc())
    )

    if job_type:
        q = q.where(Job.job_type == job_type)
    if created_by:
        q = q.where(Job.created_by == created_by)
    if since:
        q = q.where(Job.created_at >= since)
    if until:
        q = q.where(Job.created_at <= until)

    if agent_id:
        q = q.where(exists(select(1).select_from(JobRun).where(JobRun.job_id == Job.id, JobRun.agent_id == agent_id)))

    if status:
        q = q.where(computed_status == status)

    return q
