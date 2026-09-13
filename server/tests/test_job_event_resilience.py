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


def test_registration_discovers_users_without_live_refresh(job_db):
    from app.models import HostUser, Job, JobRun
    from app.routers.agent import agent_register, agent_job_event
    from app.schemas import AgentRegister, JobEvent
    from app.services.jobs import claim_queued_job_for_agent

    request = Request({'type': 'http', 'headers': []})
    registration = AgentRegister(agent_id='new-host', hostname='new-host')
    agent_register(registration, request, job_db)
    request.state.agent_auth_kind = "per-agent"
    agent_register(registration, request, job_db)
    assert len(job_db.execute(select(JobRun)).scalars().all()) == 1
    assert job_db.execute(select(Job.job_type)).scalar_one() == 'query-users'
    job = claim_queued_job_for_agent(job_db, 'new-host')
    agent_job_event(JobEvent(agent_id='new-host', job_id=job['job_id'],
        job_nonce=job['job_nonce'], status='success', exit_code=0,
        stdout=json.dumps({'users': [
            {'username': 'root', 'uid': '0', 'gid': '0'},
            {'username': 'imre', 'uid': '1000', 'gid': '1000', 'has_sudo': True},
        ]})), request, job_db)
    job_db.expire_all()
    users = job_db.execute(select(HostUser).order_by(HostUser.uid)).scalars().all()
    assert [(u.username, u.uid) for u in users] == [('root', 0), ('imre', 1000)]
    assert users[1].has_sudo is True


@pytest.mark.parametrize('stdout,status,expected', [
    ('{"users":[]}', 'success', []),
    ('{"users":[{"username":"new","uid":"1001"}]}', 'success', ['new']),
    ('{"users":42}', 'success', ['old']),
    ('not json', 'success', ['old']),
    ('{"users":[{"username":"same"},{"username":"same"}]}', 'success', ['old']),
    ('{"users":[]}', 'failed', ['old']),
])
def test_user_snapshot_replacement_is_atomic(job_db, stdout, status, expected):
    from app.models import Host, HostUser, JobRun
    from app.routers.agent import agent_job_event
    from app.schemas import JobEvent
    from app.services.jobs import create_job_with_runs

    host = job_db.execute(select(Host)).scalar_one()
    job_db.add(HostUser(host_id=host.id, username='old'))
    created = create_job_with_runs(db=job_db, job_type='query-users', payload={},
                                   agent_ids=[host.agent_id])
    run = job_db.execute(select(JobRun)).scalar_one()
    agent_job_event(JobEvent(agent_id=host.agent_id, job_id=created.job_key,
        job_nonce=run.job_nonce, status=status, stdout=stdout),
        Request({'type': 'http', 'headers': []}), job_db)
    job_db.expire_all()
    assert job_db.execute(select(HostUser.username)).scalars().all() == expected
    assert job_db.execute(select(JobRun.status)).scalar_one() == status
