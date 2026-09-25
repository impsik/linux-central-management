import asyncio
import sys
import threading
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine, select, update
from sqlalchemy.orm import sessionmaker


@pytest.fixture(autouse=True)
def isolated_app_modules(monkeypatch):
    # Settings and engines are created at import time. Keep these unit tests
    # from caching their environment before an API test configures its login.
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


@pytest.fixture()
def metrics_db(monkeypatch, tmp_path):
    from app import models
    from app.services import metrics_refresh

    engine = create_engine(f"sqlite+pysqlite:///{tmp_path / 'metrics.sqlite'}", connect_args={"check_same_thread": False})
    models.Host.metadata.create_all(engine, tables=[
        models.Host.__table__, models.HostMetricsSnapshot.__table__, models.Job.__table__, models.JobRun.__table__,
    ])
    factory = sessionmaker(bind=engine)
    monkeypatch.setattr(metrics_refresh, "SessionLocal", factory)
    monkeypatch.setattr(metrics_refresh.settings, "agent_online_grace_seconds", 30)
    yield SimpleNamespace(models=models, service=metrics_refresh, sessions=factory)
    engine.dispose()


@pytest.mark.parametrize("host_count", [100, 101, 250, 251])
@pytest.mark.parametrize("outcome", ["success", "failed"])
def test_every_host_is_selected_before_repeating_even_when_metrics_fail(metrics_db, host_count, outcome):
    models, service, sessions = metrics_db.models, metrics_db.service, metrics_db.sessions
    start = datetime.now(timezone.utc).replace(microsecond=0)
    with sessions() as db:
        db.add_all([
            models.Host(agent_id=f"node-{index:03}", hostname=f"node-{index:03}", last_seen=start)
            for index in range(host_count)
        ])
        db.commit()

    seen = set()
    batches = []
    for tick in range((host_count + 49) // 50):
        now = start + timedelta(minutes=tick)
        with sessions() as db:
            # All hosts continue sending their regular heartbeats.
            db.execute(update(models.Host).values(last_seen=now))
            db.commit()
        agent_ids, job_key = service._queue_metrics_refresh(interval_s=60, batch_limit=50, now=now)
        assert len(agent_ids) == 50
        for agent_id in agent_ids:
            # A partial final rotation may fill remaining slots with repeats,
            # but only after the final previously unvisited host was selected.
            if agent_id in seen:
                assert len(seen) == host_count
            seen.add(agent_id)
        batches.append(agent_ids)
        with sessions() as db:
            job = db.execute(select(models.Job).where(models.Job.job_key == job_key)).scalar_one()
            # Control the DB's server-default clock for simulated minute ticks.
            job.created_at = now
            db.execute(update(models.JobRun).where(models.JobRun.job_id == job.id).values(status=outcome, finished_at=now))
            if outcome == "success":
                db.add_all([
                    models.HostMetricsSnapshot(agent_id=agent_id, recorded_at=now + timedelta(seconds=1))
                    for agent_id in agent_ids
                ])
            db.commit()
    assert len(seen) == host_count

    # Once every host was attempted, the oldest batch is due again.
    now = start + timedelta(minutes=len(batches))
    with sessions() as db:
        db.execute(update(models.Host).values(last_seen=now))
        db.commit()
    agent_ids, _ = service._queue_metrics_refresh(interval_s=60, batch_limit=50, now=now)
    first_due_index = (len(batches) * 50) % host_count
    assert agent_ids[0] == batches[0][first_due_index]


def test_filtering_precedes_limit_and_preserves_oldest_first_priority(metrics_db):
    models, service, sessions = metrics_db.models, metrics_db.service, metrics_db.sessions
    now = datetime.now(timezone.utc).replace(microsecond=0)
    with sessions() as db:
        for index in range(55):
            agent_id = f"a-fresh-{index:02}"
            db.add(models.Host(agent_id=agent_id, hostname=agent_id, last_seen=now))
            # Old history must not hide the newest, still-fresh sample.
            db.add_all([
                models.HostMetricsSnapshot(agent_id=agent_id, recorded_at=now - timedelta(days=1)),
                models.HostMetricsSnapshot(agent_id=agent_id, recorded_at=now - timedelta(seconds=60)),
            ])
        for agent_id in ("b-running", "b-queued", "c-offline", "c-never-seen", "d-other-job", "e-new", "z-oldest", "f-old", ""):
            last_seen = now
            if agent_id == "c-offline":
                last_seen -= timedelta(seconds=31)
            if agent_id == "c-never-seen":
                last_seen = None
            db.add(models.Host(agent_id=agent_id, hostname=agent_id, last_seen=last_seen))
        db.add_all([
            models.HostMetricsSnapshot(agent_id="z-oldest", recorded_at=now - timedelta(minutes=20)),
            models.HostMetricsSnapshot(agent_id="f-old", recorded_at=now - timedelta(minutes=10)),
        ])
        for agent_id, job_type, status in (
            ("b-running", "query-metrics", "running"),
            ("b-queued", "query-metrics", "queued"),
            ("d-other-job", "query-services", "queued"),
        ):
            job = models.Job(job_key=agent_id, job_type=job_type, payload={}, selector={})
            db.add(job)
            db.flush()
            db.add(models.JobRun(job_id=job.id, agent_id=agent_id, status=status))
        db.commit()

    agent_ids, _ = service._queue_metrics_refresh(interval_s=60, batch_limit=3, now=now)
    assert agent_ids == ["d-other-job", "e-new", "z-oldest"]
    # Newly queued requests are excluded, including when there is no snapshot.
    agent_ids, _ = service._queue_metrics_refresh(interval_s=60, batch_limit=3, now=now)
    assert agent_ids == ["f-old"]
    assert service._queue_metrics_refresh(interval_s=60, batch_limit=3, now=now) is None


def test_recent_failed_missing_host_does_not_starve_an_older_successful_host(metrics_db):
    models, service, sessions = metrics_db.models, metrics_db.service, metrics_db.sessions
    now = datetime.now(timezone.utc).replace(microsecond=0)
    with sessions() as db:
        db.add_all([
            models.Host(agent_id="a-failing", hostname="a-failing", last_seen=now),
            models.Host(agent_id="z-working", hostname="z-working", last_seen=now),
        ])
        db.add(models.HostMetricsSnapshot(agent_id="z-working", recorded_at=now - timedelta(minutes=5)))
        job = models.Job(job_key="failed-attempt", job_type="query-metrics", payload={}, selector={}, created_at=now - timedelta(seconds=30))
        db.add(job)
        db.flush()
        db.add(models.JobRun(job_id=job.id, agent_id="a-failing", status="failed", finished_at=now))
        db.commit()
    agent_ids, _ = service._queue_metrics_refresh(interval_s=60, batch_limit=1, now=now)
    assert agent_ids == ["z-working"]


def test_db_work_owns_its_thread_and_does_not_block_event_loop(monkeypatch):
    from app.services import metrics_refresh

    release = threading.Event()
    seen = []

    async def exercise():
        loop = asyncio.get_running_loop()
        started = asyncio.Event()
        loop_thread = threading.get_ident()

        class Session:
            def __init__(self):
                seen.append(("create", threading.get_ident()))

            def __enter__(self):
                return self

            def __exit__(self, *args):
                seen.append(("close", threading.get_ident()))

            def execute(self, query):
                seen.append(("query", threading.get_ident()))
                loop.call_soon_threadsafe(started.set)
                assert release.wait(2), "the API loop could not release the DB worker"
                return SimpleNamespace(scalar_one=lambda: 0)

        monkeypatch.setattr(metrics_refresh, "SessionLocal", Session)
        task = asyncio.create_task(metrics_refresh._refresh_metrics_once(interval_s=60, batch_limit=50))
        try:
            await asyncio.wait_for(started.wait(), timeout=1)
            assert seen[0][1] != loop_thread
            task.cancel()
            await asyncio.sleep(0)
            assert not task.done()
            release.set()
            with pytest.raises(asyncio.CancelledError):
                await task
        finally:
            release.set()
            if not task.done():
                task.cancel()
            await asyncio.gather(task, return_exceptions=True)
    asyncio.run(exercise())
    assert [step for step, _ in seen] == ["create", "query", "close"]
    assert len({thread_id for _, thread_id in seen}) == 1


def test_durable_batch_is_committed_before_event_loop_wakeup(metrics_db, monkeypatch):
    models, service, sessions = metrics_db.models, metrics_db.service, metrics_db.sessions
    with sessions() as db:
        db.add(models.Host(agent_id="node", hostname="node", last_seen=datetime.now(timezone.utc)))
        db.commit()
    loop_thread = threading.get_ident()
    seen = []

    async def push(*, agent_ids, job_payload_builder):
        assert threading.get_ident() == loop_thread
        payload = job_payload_builder("node")
        with sessions() as db:
            job = db.execute(select(models.Job).where(models.Job.job_key == payload["job_id"])).scalar_one()
            assert db.execute(select(models.JobRun).where(models.JobRun.job_id == job.id)).scalar_one().status == "queued"
        seen.append(agent_ids)
    monkeypatch.setattr(service, "push_job_to_agents", push)
    asyncio.run(service._refresh_metrics_once(interval_s=60, batch_limit=50))
    assert seen == [["node"]]


def test_zero_interval_disables_background_metrics(monkeypatch):
    from app.services import metrics_refresh

    monkeypatch.setattr(metrics_refresh.settings, "metrics_background_refresh_seconds", 0)

    async def unexpected_work(**kwargs):
        raise AssertionError("disabled metrics must not enqueue work")
    monkeypatch.setattr(metrics_refresh, "_refresh_metrics_once", unexpected_work)
    asyncio.run(asyncio.wait_for(metrics_refresh.metrics_refresh_loop(asyncio.Event()), timeout=0.1))
