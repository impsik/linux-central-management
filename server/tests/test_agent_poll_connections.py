import asyncio
import sys
from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine, select, text
from sqlalchemy.orm import sessionmaker


@pytest.fixture()
def poll_db(monkeypatch, tmp_path):
    saved = {name: module for name, module in sys.modules.copy().items()
             if name == "app" or name.startswith("app.")}
    for name in saved:
        sys.modules.pop(name)
    monkeypatch.setenv("DATABASE_URL", "sqlite+pysqlite:///:memory:")
    from app import models
    from app.routers import agent

    engine = create_engine(
        f"sqlite+pysqlite:///{tmp_path / 'poll.sqlite'}",
        connect_args={"check_same_thread": False}, pool_size=1, max_overflow=0, pool_timeout=3,
    )
    models.Base.metadata.create_all(engine)
    sessions = sessionmaker(bind=engine)
    monkeypatch.setattr(agent, "SessionLocal", sessions)
    try:
        yield SimpleNamespace(engine=engine, sessions=sessions, models=models, agent=agent)
    finally:
        engine.dispose()
        for name in list(sys.modules):
            if name == "app" or name.startswith("app."):
                sys.modules.pop(name)
        sys.modules.update(saved)


def request_for(agent_id):
    return SimpleNamespace(state=SimpleNamespace(agent_auth_kind="per_agent", agent_auth_agent_id=agent_id))


def test_one_connection_serves_100_simultaneous_idle_polls(poll_db, monkeypatch):
    with poll_db.sessions() as db:
        db.add_all([poll_db.models.Host(agent_id=f"host-{i}", hostname=f"host-{i}") for i in range(100)])
        db.commit()

    async def exercise():
        entered = set()
        all_waiting = asyncio.Event()
        release = asyncio.Event()

        async def idle(agent_id, timeout):
            entered.add(agent_id)
            if len(entered) == 100:
                all_waiting.set()
            await release.wait()
            return None

        monkeypatch.setattr(poll_db.agent.dispatcher, "pop_job", idle)
        tasks = [asyncio.create_task(poll_db.agent.agent_next_job(f"host-{i}", request_for(f"host-{i}")))
                 for i in range(100)]
        try:
            await asyncio.wait_for(all_waiting.wait(), timeout=10)
            assert poll_db.engine.pool.checkedout() == 0
            # Another request can use the only connection while all polls wait.
            with poll_db.sessions() as db:
                assert db.execute(select(poll_db.models.Host)).scalars().first() is not None
            release.set()
            assert await asyncio.gather(*tasks) == [{"job": None}] * 100
        finally:
            release.set()
            await asyncio.gather(*tasks, return_exceptions=True)

    asyncio.run(exercise())


def test_pool_wait_does_not_block_event_loop(poll_db, monkeypatch):
    with poll_db.sessions() as db:
        db.add(poll_db.models.Host(agent_id="waiting", hostname="waiting"))
        db.commit()

    async def no_job(*args, **kwargs):
        return None

    monkeypatch.setattr(poll_db.agent.dispatcher, "pop_job", no_job)
    held = poll_db.sessions()
    held.execute(text("SELECT 1"))

    async def exercise():
        task = asyncio.create_task(poll_db.agent.agent_next_job("waiting", request_for("waiting")))
        try:
            # This timer must run while the worker is waiting for the pool.
            await asyncio.sleep(.05)
            assert not task.done()
            held.close()
            assert await asyncio.wait_for(task, timeout=2) == {"job": None}
        finally:
            held.close()
            await asyncio.gather(task, return_exceptions=True)

    asyncio.run(exercise())


def test_stale_wakeup_falls_back_to_durable_queue(poll_db, monkeypatch):
    from app.services.jobs import create_job_with_runs

    with poll_db.sessions() as db:
        db.add(poll_db.models.Host(agent_id="wake", hostname="wake"))
        db.commit()

    expected = {}

    async def wake(*args, **kwargs):
        assert poll_db.engine.pool.checkedout() == 0
        with poll_db.sessions() as db:
            job = create_job_with_runs(db=db, job_type="query-metrics", payload={}, agent_ids=["wake"])
            expected["id"] = job.job_key
        return {"job_id": "already-consumed-job"}

    monkeypatch.setattr(poll_db.agent.dispatcher, "pop_job", wake)
    result = asyncio.run(poll_db.agent.agent_next_job("wake", request_for("wake")))
    assert result["job"]["job_id"] == expected["id"]
    assert result["job"]["job_nonce"]
    assert poll_db.engine.pool.checkedout() == 0
