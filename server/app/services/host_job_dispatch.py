from __future__ import annotations

from fastapi import HTTPException
from sqlalchemy.orm import Session

from .db_utils import transaction
from .job_wait import wait_for_job_run
from .jobs import create_job_with_runs, push_job_to_agents


def dispatch_host_job(
    *,
    db: Session,
    agent_id: str,
    job_type: str,
    payload: dict,
    job_payload_builder=None,
):
    with transaction(db):
        created = create_job_with_runs(
            db=db,
            job_type=job_type,
            payload=payload,
            agent_ids=[agent_id],
            commit=False,
        )
    job_id = created.job.id

    if job_payload_builder is None:
        job_payload_builder = lambda aid: {"job_id": created.job_key, "type": job_type, **payload}

    push_kwargs = {
        "agent_ids": [agent_id],
        "job_payload_builder": job_payload_builder,
    }
    return created, job_id, push_kwargs


async def push_dispatched_host_job(*, push_kwargs: dict) -> None:
    await push_job_to_agents(**push_kwargs)


async def wait_for_host_job_or_504(
    *,
    job_id,
    agent_id: str,
    timeout_s: float,
    timeout_message: str,
    poll_interval_s: float = 0.3,
):
    res = await wait_for_job_run(
        job_id=job_id,
        agent_id=agent_id,
        timeout_s=timeout_s,
        poll_interval_s=poll_interval_s,
    )
    if not res.run:
        raise HTTPException(504, timeout_message)
    return res.run


def require_successful_run(run, *, error_message: str, include_stdout: bool = False):
    if run.status == "failed":
        msg = run.error or run.stderr or (run.stdout if include_stdout else None) or "Unknown error"
        raise HTTPException(500, f"{error_message}: {msg}")
    return run


def parse_json_run_stdout(run, default):
    from .json_utils import loads_or

    return loads_or(run.stdout, default)
