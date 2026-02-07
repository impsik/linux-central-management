from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import AnsibleRun


def create_run(
    *,
    db: Session,
    playbook: str,
    targets: list[str],
    extra_vars_redacted: dict[str, Any],
    created_by: str | None,
) -> AnsibleRun:
    run_key = uuid.uuid4().hex
    run = AnsibleRun(
        run_key=run_key,
        playbook=playbook,
        created_by=created_by,
        targets=targets,
        extra_vars=extra_vars_redacted or {},
        status="running",
        created_at=datetime.now(timezone.utc),
    )
    db.add(run)
    db.flush()
    return run


def get_run_by_key(db: Session, run_id: str) -> AnsibleRun:
    run = db.execute(select(AnsibleRun).where(AnsibleRun.run_key == run_id)).scalar_one_or_none()
    if not run:
        raise HTTPException(404, "run not found")
    return run
