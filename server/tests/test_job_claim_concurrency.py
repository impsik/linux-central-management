"""Opt-in PostgreSQL concurrency regressions on an explicitly provided test DB.

Set FLEET_TEST_POSTGRES_URL to a migrated, disposable database. Fixtures only
create uniquely named jobs/runs and remove those rows after each test.
"""
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import os
import sys
import threading
from types import SimpleNamespace
import uuid

import pytest
from sqlalchemy import create_engine, delete, select, text
from sqlalchemy.orm import sessionmaker


@pytest.fixture
def postgres_jobs(monkeypatch):
    url = os.getenv("FLEET_TEST_POSTGRES_URL")
    if not url:
        pytest.skip("requires an explicit disposable FLEET_TEST_POSTGRES_URL")
    saved = {name: module for name, module in sys.modules.copy().items()
             if name == "app" or name.startswith("app.")}
    for name in saved:
        sys.modules.pop(name)
    monkeypatch.setenv("DATABASE_URL", "sqlite+pysqlite:///:memory:")
    engine = None
    keys = []
    try:
        from app import models
        from app.services import jobs

        engine = create_engine(url, pool_size=2, max_overflow=0, pool_timeout=3)
        assert engine.dialect.name == "postgresql"
        sessions = sessionmaker(bind=engine, autoflush=False)
        monkeypatch.setattr(jobs.settings, "job_run_stale_after_seconds", 60)
        monkeypatch.setattr(jobs.settings, "job_run_max_retries", 1)

        def seed(agent_count=1, stale=False):
            prefix = "claim-concurrency-" + uuid.uuid4().hex
            agents = [f"{prefix}-{i}" for i in range(agent_count)]
            with sessions() as db:
                created = jobs.create_job_with_runs(
                    db=db, job_type="query-metrics", payload={},
                    agent_ids=agents, created_by="concurrency-test",
                )
                keys.append(created.job_key)
                if stale:
                    run = db.execute(select(models.JobRun).where(models.JobRun.job_id == created.job.id)).scalar_one()
                    run.status = "running"
                    run.started_at = datetime.now(timezone.utc) - timedelta(minutes=2)
                    run.job_nonce = "abandoned-attempt"
                    db.commit()
                return created.job_key, agents

        yield SimpleNamespace(jobs=jobs, models=models, sessions=sessions, seed=seed)
    finally:
        if engine is not None:
            if keys:
                with sessions.begin() as db:
                    db.execute(delete(models.Job).where(models.Job.job_key.in_(keys)))
            engine.dispose()
        for name in list(sys.modules):
            if name == "app" or name.startswith("app."):
                sys.modules.pop(name)
        sys.modules.update(saved)


@contextmanager
def claim_waiting_to_commit(stack, agent_id):
    ready = threading.Event()
    release = threading.Event()

    def claim():
        with stack.sessions() as db:
            commit = db.commit

            def delayed_commit():
                db.flush()
                ready.set()
                assert release.wait(4), "test did not release the first claim"
                commit()

            db.commit = delayed_commit
            return stack.jobs.claim_queued_job_for_agent(db, agent_id)

    with ThreadPoolExecutor(max_workers=1) as workers:
        future = workers.submit(claim)
        try:
            assert ready.wait(3), "first claim did not reach its commit"
            yield future
        finally:
            release.set()
            future.result(timeout=3)


def claim_on_second_connection(stack, agent_id):
    with stack.sessions() as db:
        # A broken stale recovery used to wait on its unconditional UPDATE.
        # Bound that failure rather than letting the test wait for the first
        # claim's release and accidentally hiding the race.
        db.execute(text("SET LOCAL lock_timeout = '500ms'"))
        db.execute(text("SET LOCAL statement_timeout = '2s'"))
        return stack.jobs.claim_queued_job_for_agent(db, agent_id)


def test_parallel_agents_claim_different_runs_of_the_same_batch(postgres_jobs):
    stack = postgres_jobs
    key, agents = stack.seed(agent_count=2)

    with claim_waiting_to_commit(stack, agents[0]) as first:
        second = claim_on_second_connection(stack, agents[1])
        assert second is not None, "locking the shared Job parent skipped another agent's run"
        assert second["job_id"] == key
        assert not first.done()

    assert first.result()["job_id"] == key
    assert first.result()["job_nonce"] != second["job_nonce"]
    with stack.sessions() as db:
        states = db.execute(select(stack.models.JobRun.status).where(stack.models.JobRun.agent_id.in_(agents))).scalars().all()
        assert states == ["running", "running"]


def test_overlapping_stale_claim_does_not_retry_or_rotate_nonce_twice(postgres_jobs):
    stack = postgres_jobs
    key, agents = stack.seed(stale=True)

    with claim_waiting_to_commit(stack, agents[0]) as first:
        assert claim_on_second_connection(stack, agents[0]) is None
        assert not first.done()

    claimed = first.result()
    assert claimed["job_id"] == key
    assert claimed["job_nonce"] != "abandoned-attempt"
    assert claim_on_second_connection(stack, agents[0]) is None
    with stack.sessions() as db:
        run = db.execute(select(stack.models.JobRun).where(stack.models.JobRun.agent_id == agents[0])).scalar_one()
        assert run.status == "running"
        assert run.retry_count == 1
        assert run.job_nonce == claimed["job_nonce"]


def test_scheduler_workers_dispatch_a_due_cronjob_only_once(postgres_jobs, monkeypatch):
    import asyncio
    from app.services import cronjobs
    stack = postgres_jobs
    models = stack.models
    user_id, cron_id = uuid.uuid4(), uuid.uuid4()
    created_keys = []
    original_create = cronjobs.create_job_with_runs

    def record_create(**kwargs):
        created = original_create(**kwargs)
        created_keys.append(created.job_key)
        return created

    async def no_push(**kwargs):
        return None

    monkeypatch.setattr(cronjobs, 'create_job_with_runs', record_create)
    monkeypatch.setattr(cronjobs, 'push_job_to_agents', no_push)
    with stack.sessions.begin() as db:
        db.add(models.AppUser(id=user_id, username=f'cron-concurrency-{user_id}', password_hash='unused', role='admin'))
        db.flush()
        db.add(models.CronJob(id=cron_id, user_id=user_id, action='dist-upgrade', status='scheduled',
                              run_at=datetime.now(timezone.utc) - timedelta(minutes=1), selector={'agent_ids': ['concurrency-node']}))
    loaded = threading.Barrier(2)

    def dispatch():
        with stack.sessions() as db:
            db.execute(text("SET LOCAL statement_timeout = '5s'"))
            stale = db.get(models.CronJob, cron_id)
            loaded.wait(timeout=3)
            asyncio.run(cronjobs._dispatch_one(db, stale))

    try:
        with ThreadPoolExecutor(max_workers=2) as workers:
            futures = [workers.submit(dispatch) for _ in range(2)]
            for future in futures:
                future.result(timeout=10)
        with stack.sessions() as db:
            runs = db.scalars(select(models.CronJobRun).where(models.CronJobRun.cron_job_id == cron_id)).all()
            assert len(runs) == 1
            assert runs[0].status == 'success'
            assert len(created_keys) == 1
    finally:
        with stack.sessions.begin() as db:
            db.execute(delete(models.CronJob).where(models.CronJob.id == cron_id))
            db.execute(delete(models.AppUser).where(models.AppUser.id == user_id))
            if created_keys:
                db.execute(delete(models.Job).where(models.Job.job_key.in_(created_keys)))
