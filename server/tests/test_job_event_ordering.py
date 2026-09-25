from datetime import datetime, timezone
from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from starlette.requests import Request


@pytest.mark.parametrize('finished', ['success', 'failed'])
@pytest.mark.parametrize('late', ['running', 'success', 'failed'])
def test_late_event_cannot_reopen_or_overwrite_completed_attempt(finished, late):
    from app.models import Base, Host, Job, JobRun
    from app.routers.agent import agent_job_event
    from app.schemas import JobEvent

    engine = create_engine('sqlite://')
    Base.metadata.create_all(engine)
    request = Request({'type': 'http', 'method': 'POST', 'path': '/agent/job-event', 'headers': []})
    request.state.agent_auth_kind = 'per_agent'
    request.state.agent_auth_agent_id = 'node'
    try:
        with Session(engine) as db:
            job = Job(job_key='ordered-job', job_type='test', payload={}, selector={})
            db.add(job)
            db.flush()
            completed = datetime.now(timezone.utc)
            run = JobRun(job_id=job.id, agent_id='node', job_nonce='first-attempt', status=finished, stdout='original', finished_at=completed)
            db.add_all([run, Host(agent_id='node', hostname='node')])
            db.commit()
            original_finished = run.finished_at
            response = agent_job_event(JobEvent(agent_id='node', job_id=job.job_key, job_nonce='first-attempt', status=late, stdout='late result'), request, db)
            assert response == {'ok': True}
            db.refresh(run)
            assert (run.status, run.stdout, run.finished_at) == (finished, 'original', original_finished)
            # A deliberate new attempt can still finish normally with its new nonce.
            run.status = 'queued'
            run.job_nonce = 'second-attempt'
            db.commit()
            agent_job_event(JobEvent(agent_id='node', job_id=job.job_key, job_nonce='second-attempt', status='success', stdout='new result'), request, db)
            db.refresh(run)
            assert (run.status, run.stdout) == ('success', 'new result')
    finally:
        engine.dispose()


def test_job_wait_database_query_runs_outside_event_loop(monkeypatch):
    import asyncio
    import threading
    from app.services import job_wait
    event_loop_thread = threading.get_ident()
    result_row = SimpleNamespace(status='success')
    class FakeSession:
        def __enter__(self):
            assert threading.get_ident() != event_loop_thread
            return self
        def __exit__(self, *args):
            pass
        def execute(self, statement):
            return SimpleNamespace(scalar_one_or_none=lambda: result_row)
        def expunge(self, row):
            assert row is result_row
    monkeypatch.setattr(job_wait, 'SessionLocal', FakeSession)
    result = asyncio.run(job_wait.wait_for_job_run(job_id='job', agent_id='node', timeout_s=1))
    assert result.run is result_row
    assert result.status == 'success'
