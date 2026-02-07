from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import Callable, Literal, Optional

from sqlalchemy import select

from ..db import SessionLocal
from ..models import JobRun

JobStatus = Literal["queued", "running", "success", "failed"]


@dataclass
class JobWaitResult:
    status: JobStatus
    run: Optional[JobRun]
    polls: int
    elapsed_s: float


async def wait_for_job_run(
    *,
    job_id,
    agent_id: str,
    timeout_s: float,
    poll_interval_s: float = 0.3,
    on_poll: Callable[[int, str], None] | None = None,
) -> JobWaitResult:
    """Poll job_runs until a run is finished.

    Uses fresh DB sessions to avoid stale ORM state.
    """

    start = time.time()
    polls = 0
    while time.time() - start < timeout_s:
        polls += 1
        db = SessionLocal()
        try:
            db.expire_all()
            run = db.execute(
                select(JobRun).where(JobRun.job_id == job_id, JobRun.agent_id == agent_id)
            ).scalar_one_or_none()
            if run and run.status in ("success", "failed"):
                # Detach by expunging so callers don't rely on a live session.
                db.expunge(run)
                return JobWaitResult(status=run.status, run=run, polls=polls, elapsed_s=time.time() - start)
        finally:
            db.close()

        if on_poll is not None and polls % 10 == 0:
            on_poll(polls, agent_id)

        await asyncio.sleep(poll_interval_s)

    return JobWaitResult(status="queued", run=None, polls=polls, elapsed_s=time.time() - start)
