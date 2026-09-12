"""Job results must survive malformed optional inventory and metrics payloads."""
import json
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from starlette.requests import Request


@pytest.fixture
def job_db():
    from app.db import Base
    from app.models import Host

    engine = create_engine('sqlite:///:memory:')
    Base.metadata.create_all(engine)
    with Session(engine, autoflush=False) as db:
        db.add(Host(agent_id='resilience-agent', hostname='resilience-agent'))
        db.commit()
        yield db
    engine.dispose()


@pytest.mark.parametrize(('job_type', 'stdout'), [
    ('cve-check', 'not json'),
    ('cve-check', '[]'),
    ('query-metrics', '{"metrics":{"cpu":{"vcpus":"invalid"}}}'),
    ('query-pkg-updates', json.dumps({'updates': [
        {'name': 'duplicate'}, {'name': 'duplicate'}]})),
    ('query-pkg-updates', '{"updates":42}'),
])
def test_cache_failure_preserves_completion(job_db, job_type, stdout):
    from app.models import Host, HostPackageUpdate, JobRun
    from app.routers.agent import agent_job_event
    from app.schemas import JobEvent
    from app.services.jobs import create_job_with_runs

    db = job_db
    host = db.execute(select(Host)).scalar_one()
    db.add(HostPackageUpdate(host_id=host.id, name='old-package', update_available=True))
    created = create_job_with_runs(db=db, job_type=job_type, payload={},
                                   agent_ids=[host.agent_id])
    run = db.execute(select(JobRun)).scalar_one()
    run.status = 'running'
    db.commit()
    result = agent_job_event(JobEvent(agent_id=host.agent_id, job_id=created.job_key,
        job_nonce=run.job_nonce, status='success', exit_code=0, stdout=stdout),
        Request({'type': 'http', 'headers': []}), db)
    assert result == {'ok': True}
    db.expire_all()
    saved = db.execute(select(JobRun)).scalar_one()
    assert saved.status == 'success'
    assert saved.finished_at is not None
    assert saved.exit_code == 0
    assert saved.stdout == stdout
    assert db.execute(select(HostPackageUpdate.name)).scalars().all() == ['old-package']


def test_stale_retry_rejects_previous_attempt_event(job_db, monkeypatch):
    from fastapi import HTTPException
    from app.config import settings
    from app.models import JobRun
    from app.routers.agent import agent_job_event
    from app.schemas import JobEvent
    from app.services.jobs import create_job_with_runs, claim_queued_job_for_agent

    monkeypatch.setattr(settings, 'job_run_stale_after_seconds', 60)
    monkeypatch.setattr(settings, 'job_run_max_retries', 1)
    created = create_job_with_runs(db=job_db, job_type='query-metrics', payload={},
                                   agent_ids=['resilience-agent'])
    first = claim_queued_job_for_agent(job_db, 'resilience-agent')
    run = job_db.execute(select(JobRun)).scalar_one()
    run.started_at = datetime.now(timezone.utc) - timedelta(minutes=2)
    job_db.commit()
    retry = claim_queued_job_for_agent(job_db, 'resilience-agent')
    assert retry['job_nonce'] != first['job_nonce']
    with pytest.raises(HTTPException) as exc:
        agent_job_event(JobEvent(agent_id='resilience-agent', job_id=created.job_key,
            job_nonce=first['job_nonce'], status='success', exit_code=0),
            Request({'type': 'http', 'headers': []}), job_db)
    assert exc.value.status_code == 403
    job_db.expire_all()
    assert job_db.execute(select(JobRun.status)).scalar_one() == 'running'
    agent_job_event(JobEvent(agent_id='resilience-agent', job_id=created.job_key,
        job_nonce=retry['job_nonce'], status='success', exit_code=0),
        Request({'type': 'http', 'headers': []}), job_db)
    job_db.expire_all()
    assert job_db.execute(select(JobRun.status)).scalar_one() == 'success'
