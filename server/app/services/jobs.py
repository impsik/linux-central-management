from __future__ import annotations

import uuid
from dataclasses import dataclass

from sqlalchemy.orm import Session

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
            db.add(JobRun(job_id=job.id, agent_id=aid, status="queued"))

        return job

    if commit:
        with transaction(db):
            job = _create()
    else:
        job = _create()

    return CreatedJob(job=job, job_key=job_key)


async def push_job_to_agents(*, agent_ids: list[str], job_payload_builder) -> None:
    """Push the in-memory job message to each agent queue."""
    for aid in agent_ids:
        await dispatcher.push_job(aid, job_payload_builder(aid))
