from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import Callable, Literal, Optional

from sqlalchemy import select

from ..db import SessionLocal
from ..models import JobRun
from .background import run_blocking

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

    def read_finished_run():
        with SessionLocal() as db:
            run = db.execute(
                select(JobRun).where(JobRun.job_id == job_id, JobRun.agent_id == agent_id)
            ).scalar_one_or_none()
            if run and run.status in ("success", "failed"):
                db.expunge(run)
                return run
        return None

    start = time.monotonic()
    polls = 0
    while time.monotonic() - start < timeout_s:
        polls += 1
        run = await run_blocking(read_finished_run)
        if run is not None:
            return JobWaitResult(status=run.status, run=run, polls=polls, elapsed_s=time.monotonic() - start)

        if on_poll is not None and polls % 10 == 0:
            on_poll(polls, agent_id)

        await asyncio.sleep(poll_interval_s)

    return JobWaitResult(status="queued", run=None, polls=polls, elapsed_s=time.monotonic() - start)
