import asyncio
from datetime import datetime, timedelta, timezone
import importlib.util
from pathlib import Path
import sys
import threading
from types import SimpleNamespace
import uuid

import pytest
from sqlalchemy import create_engine, event, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool


NOW = datetime(2026, 9, 15, tzinfo=timezone.utc)


@pytest.fixture
def isolated_app_modules(monkeypatch):
    # The app constructs settings/engines at import time. Use private modules
    # here and restore the complete previous module tree after each test, so API
    # tests can still bootstrap their own credentials and database afterwards.
    saved = {name: module for name, module in sys.modules.copy().items()
             if name == "app" or name.startswith("app.")}
    for name in saved:
        sys.modules.pop(name)
    monkeypatch.setenv("DATABASE_URL", "sqlite+pysqlite:///:memory:")
    try:
        yield
    finally:
        for name in list(sys.modules):
            if name == "app" or name.startswith("app."):
                sys.modules.pop(name)
        sys.modules.update(saved)


@pytest.fixture
def retention(monkeypatch, isolated_app_modules):
    from app.db import Base
    from app.services import job_retention

    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    with engine.connect() as conn:
        conn.exec_driver_sql("PRAGMA foreign_keys=ON")
    Base.metadata.create_all(engine)
    sessions = sessionmaker(bind=engine)
    monkeypatch.setattr(job_retention, "SessionLocal", sessions)
    monkeypatch.setattr(job_retention, "settings", SimpleNamespace(
        metrics_job_retention_days=7,
        metrics_job_cleanup_interval_seconds=300,
        metrics_job_cleanup_batch_size=5000,
    ))
    yield job_retention, sessions, engine
    engine.dispose()


def add_job(sessions, *, source="metrics_refresh_loop", creator="api", kind="query-metrics", runs=None):
    from app.models import Job, JobRun

    with sessions.begin() as db:
        job = Job(job_key=str(uuid.uuid4()), created_by=creator, job_type=kind,
                  payload={"source": source}, selector={}, created_at=NOW - timedelta(days=9))
        db.add(job)
        db.flush()
        for index, run in enumerate(runs if runs is not None else [{}]):
            values = {"status": "success", "finished_at": NOW - timedelta(days=8),
                      "exit_code": 0, "stdout": "old metrics " * 1000, **run}
            db.add(JobRun(job_id=job.id, agent_id=f"node-{index}", **values))
        return job.id, job.job_key


def test_cleanup_only_old_successful_background_metrics(retention):
    from app.models import Job, JobRun

    worker, sessions, _ = retention
    removed_id, _ = add_job(sessions)
    preserved = [
        add_job(sessions, creator="admin")[0],
        add_job(sessions, source="manual")[0],
        add_job(sessions, kind="pkg-upgrade")[0],
        add_job(sessions, runs=[{"status": "failed", "exit_code": 1}])[0],
        add_job(sessions, runs=[{"status": "running", "finished_at": None}])[0],
        add_job(sessions, runs=[{"status": "queued", "finished_at": None}])[0],
        add_job(sessions, runs=[{"finished_at": NOW - timedelta(days=7)}])[0],
        add_job(sessions, runs=[{"finished_at": None}])[0],
    ]

    assert worker.cleanup_metrics_job_history(now=NOW) == {"job_runs_deleted": 1, "jobs_deleted": 1}
    with sessions() as db:
        assert db.get(Job, removed_id) is None
        assert set(db.scalars(select(Job.id))) == set(preserved)
        assert set(db.scalars(select(JobRun.job_id))) == set(preserved)
    assert worker.cleanup_metrics_job_history(now=NOW) == {"job_runs_deleted": 0, "jobs_deleted": 0}


def test_parent_survives_remaining_failed_active_or_recent_runs(retention):
    from app.models import Job, JobRun

    worker, sessions, _ = retention
    job_id, _ = add_job(sessions, runs=[{}, {"status": "failed"},
        {"status": "running", "finished_at": None}, {"finished_at": NOW}])

    assert worker.cleanup_metrics_job_history(now=NOW) == {"job_runs_deleted": 1, "jobs_deleted": 0}
    with sessions() as db:
        assert db.get(Job, job_id) is not None
        assert set(db.scalars(select(JobRun.agent_id))) == {"node-1", "node-2", "node-3"}


def test_cleanup_is_bounded_and_deletes_parent_only_after_last_batch(retention):
    from app.models import Job, JobRun

    worker, sessions, _ = retention
    worker.settings.metrics_job_cleanup_batch_size = 2
    job_id, _ = add_job(sessions, runs=[{}, {}, {}])

    assert worker.cleanup_metrics_job_history(now=NOW) == {"job_runs_deleted": 2, "jobs_deleted": 0}
    with sessions() as db:
        assert db.get(Job, job_id) is not None
        assert len(list(db.scalars(select(JobRun.id)))) == 1
    assert worker.cleanup_metrics_job_history(now=NOW) == {"job_runs_deleted": 1, "jobs_deleted": 1}


@pytest.mark.parametrize("reference", ["cron", "campaign", "approval", "audit_event", "audit_log"])
def test_referenced_metrics_jobs_and_results_are_preserved(retention, reference):
    from app.models import (AppUser, AuditEvent, AuditLog, CronJob, CronJobRun,
                            HighRiskActionRequest, Job, JobRun, PatchCampaign, PatchCampaignHost)

    worker, sessions, _ = retention
    job_id, job_key = add_job(sessions)
    with sessions.begin() as db:
        user = AppUser(username="admin", password_hash="unused", role="admin")
        db.add(user)
        db.flush()
        if reference == "cron":
            cron = CronJob(user_id=user.id, run_at=NOW, action="inventory-now")
            db.add(cron)
            db.flush()
            db.add(CronJobRun(cron_job_id=cron.id, job_key=job_key))
        elif reference == "campaign":
            campaign = PatchCampaign(campaign_key="campaign", kind="security-updates", window_start=NOW, window_end=NOW)
            db.add(campaign)
            db.flush()
            db.add(PatchCampaignHost(campaign_id=campaign.id, agent_id="node-0", job_key_reboot_check=job_key))
        elif reference == "approval":
            db.add(HighRiskActionRequest(user_id=user.id, action="dist-upgrade", execution_ref=job_key))
        elif reference == "audit_event":
            db.add(AuditEvent(action="job.cancel", target_type="job", target_id=job_key))
        else:
            db.add(AuditLog(action="review", entity_type="job", entity_key=job_key))

    assert worker.cleanup_metrics_job_history(now=NOW) == {"job_runs_deleted": 0, "jobs_deleted": 0}
    with sessions() as db:
        assert db.get(Job, job_id) is not None
        assert len(list(db.scalars(select(JobRun.id)))) == 1


def test_failure_rolls_back_run_and_parent_deletion(retention):
    from app.models import Job, JobRun

    worker, sessions, engine = retention
    job_id, _ = add_job(sessions)

    def fail_parent_delete(conn, cursor, statement, parameters, context, executemany):
        if statement.startswith("DELETE FROM jobs "):
            raise RuntimeError("simulated parent delete failure")

    event.listen(engine, "before_cursor_execute", fail_parent_delete)
    try:
        with pytest.raises(RuntimeError, match="simulated"):
            worker.cleanup_metrics_job_history(now=NOW)
    finally:
        event.remove(engine, "before_cursor_execute", fail_parent_delete)
    with sessions() as db:
        assert db.get(Job, job_id) is not None
        assert len(list(db.scalars(select(JobRun.id)))) == 1


def test_additional_parent_foreign_key_prevents_cascade_cleanup(retention):
    from sqlalchemy import Column, ForeignKey, Integer, Table
    from sqlalchemy.dialects.postgresql import UUID
    from app.db import Base
    from app.models import Job, JobRun

    worker, sessions, engine = retention
    reference = Table("retention_test_reference", Base.metadata,
        Column("id", Integer, primary_key=True),
        Column("job_id", UUID(as_uuid=True), ForeignKey("jobs.id", ondelete="CASCADE")),
    )
    reference.create(engine)
    try:
        job_id, _ = add_job(sessions)
        with sessions.begin() as db:
            db.execute(reference.insert().values(id=1, job_id=job_id))

        assert worker.cleanup_metrics_job_history(now=NOW) == {"job_runs_deleted": 0, "jobs_deleted": 0}
        with sessions() as db:
            assert db.get(Job, job_id) is not None
            assert len(list(db.scalars(select(JobRun.id)))) == 1
            assert db.scalar(select(reference.c.job_id)) == job_id
    finally:
        reference.drop(engine)
        Base.metadata.remove(reference)


def test_cleanup_does_not_remove_metrics_snapshots_or_load_history(retention):
    from app.models import HostLoadMetric, HostMetricsSnapshot

    worker, sessions, _ = retention
    add_job(sessions)
    with sessions.begin() as db:
        db.add(HostMetricsSnapshot(agent_id="node-0", load_1min="1.2", recorded_at=NOW - timedelta(days=8)))
        db.add(HostLoadMetric(agent_id="node-0", load_1min="1.2", load_5min="1", load_15min="0.8",
                              recorded_at=NOW - timedelta(days=8)))

    assert worker.cleanup_metrics_job_history(now=NOW)["job_runs_deleted"] == 1
    with sessions() as db:
        assert list(db.scalars(select(HostMetricsSnapshot.load_1min))) == ["1.2"]
        assert list(db.scalars(select(HostLoadMetric.load_1min))) == ["1.2"]


def test_retention_index_migration_round_trip(retention):
    from alembic.migration import MigrationContext
    from alembic.operations import Operations
    from sqlalchemy import inspect

    _, _, engine = retention
    migration_path = Path(__file__).resolve().parents[1] / "alembic/versions/20260914_01_metrics_job_retention.py"
    spec = importlib.util.spec_from_file_location("retention_migration", migration_path)
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)
    index_name = "ix_job_runs_status_finished_id"

    with engine.begin() as conn, Operations.context(MigrationContext.configure(conn)):
        migration.downgrade()
        assert index_name not in {index["name"] for index in inspect(conn).get_indexes("job_runs")}
        migration.upgrade()
        indexes = {index["name"]: index for index in inspect(conn).get_indexes("job_runs")}
        assert indexes[index_name]["column_names"] == ["status", "finished_at", "id"]


def test_disabled_retention_does_not_open_database(retention, monkeypatch):
    worker, _, _ = retention
    worker.settings.metrics_job_retention_days = 0
    monkeypatch.setattr(worker, "SessionLocal", lambda: pytest.fail("must not connect"))

    assert worker.cleanup_metrics_job_history(now=NOW) == {"job_runs_deleted": 0, "jobs_deleted": 0}
    asyncio.run(worker.job_retention_loop(asyncio.Event()))


def test_loop_runs_off_event_loop_and_joins_worker_on_cancellation(retention, monkeypatch):
    worker, _, _ = retention
    started = threading.Event()
    release = threading.Event()
    completed = threading.Event()
    thread_ids = []

    async def immediate_timeout(awaitable, timeout):
        awaitable.close()
        raise asyncio.TimeoutError

    def blocking_cleanup():
        thread_ids.append(threading.get_ident())
        started.set()
        release.wait(timeout=3)
        completed.set()
        return {"job_runs_deleted": 0, "jobs_deleted": 0}

    monkeypatch.setattr(worker.asyncio, "wait_for", immediate_timeout)
    monkeypatch.setattr(worker, "cleanup_metrics_job_history", blocking_cleanup)

    async def check():
        task = asyncio.create_task(worker.job_retention_loop(asyncio.Event()))
        try:
            for _ in range(100):
                if started.is_set():
                    break
                await asyncio.sleep(0.01)
            assert started.is_set()
            assert len(thread_ids) == 1
            assert thread_ids[0] != threading.get_ident()
            task.cancel()
            await asyncio.sleep(0.01)
            assert not task.done()
        finally:
            release.set()
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
        assert completed.is_set()

    asyncio.run(check())
