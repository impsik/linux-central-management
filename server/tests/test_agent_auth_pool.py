import asyncio
import hashlib
import hmac
import sys
import threading
import time
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker
from starlette.requests import Request


@pytest.fixture
def auth_db(monkeypatch, tmp_path):
    saved = {name: module for name, module in sys.modules.copy().items()
             if name == "app" or name.startswith("app.")}
    for name in saved:
        sys.modules.pop(name)
    monkeypatch.setenv("DATABASE_URL", "sqlite+pysqlite:///:memory:")
    from app import models
    from app.services import agent_auth

    engine = create_engine(
        f"sqlite+pysqlite:///{tmp_path / 'auth.sqlite'}",
        connect_args={"check_same_thread": False},
        pool_size=1, max_overflow=0, pool_timeout=2,
    )
    models.Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)
    token = "per-agent-test-token"
    with factory.begin() as db:
        db.add_all([models.Host(agent_id=f"node-{i:03}", hostname=f"node-{i:03}",
                               agent_token_hash=agent_auth.hash_agent_token(token)) for i in range(80)])

    events = []

    class TrackedSession(Session):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.owner = threading.get_ident()
            events.append(("create", self.owner))

        def execute(self, *args, **kwargs):
            assert threading.get_ident() == self.owner
            events.append(("execute", self.owner))
            return super().execute(*args, **kwargs)

        def close(self):
            assert threading.get_ident() == self.owner
            super().close()
            events.append(("close", self.owner))

    monkeypatch.setattr(agent_auth, "SessionLocal", sessionmaker(bind=engine, class_=TrackedSession))
    monkeypatch.setattr(agent_auth, "settings", SimpleNamespace(
        agent_shared_token="registration-only-token", agent_shared_token_allow_runtime=False,
        allow_insecure_no_agent_token=False, agent_hmac_required=True, agent_hmac_max_skew_seconds=300,
    ))
    try:
        yield SimpleNamespace(service=agent_auth, engine=engine, sessions=factory, models=models,
                              token=token, events=events)
    finally:
        engine.dispose()
        for name in list(sys.modules):
            if name == "app" or name.startswith("app."):
                sys.modules.pop(name)
        sys.modules.update(saved)


def signed_request(token, idx=0, *, receive=None, signature=None):
    path = "/agent/inventory/packages"
    query = f"sequence={idx}"
    body = b'{"packages":[]}'
    timestamp = str(int(time.time()))
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    message = "\n".join(["POST", f"{path}?{query}", timestamp, hashlib.sha256(body).hexdigest()])
    signature = signature or hmac.new(token_hash.encode(), message.encode(), hashlib.sha256).hexdigest()
    headers = {"X-Fleet-Agent-ID": f"node-{idx:03}", "X-Fleet-Agent-Token": token,
               "X-Fleet-Agent-Timestamp": timestamp, "X-Fleet-Agent-Signature": signature}

    async def immediate_body():
        return {"type": "http.request", "body": body, "more_body": False}

    request = Request({
        "type": "http", "method": "POST", "scheme": "http", "path": path,
        "query_string": query.encode(), "server": ("fleet.test", 80),
        "client": ("192.0.2.1", 12345),
        "headers": [(name.lower().encode(), value.encode()) for name, value in headers.items()],
    }, receive=receive or immediate_body)
    return request


def test_eighty_auth_requests_release_single_connection_before_body_wait(auth_db):
    async def scenario():
        all_bodies_waiting = asyncio.Event()
        release_bodies = asyncio.Event()
        waiting = []

        async def slow_body():
            waiting.append(True)
            if len(waiting) == 80:
                all_bodies_waiting.set()
            await release_bodies.wait()
            return {"type": "http.request", "body": b'{"packages":[]}', "more_body": False}

        # Make all token lookups wait for a pool slot first. This wait must take
        # place on worker threads so the API loop can return this connection.
        held = auth_db.engine.connect()
        requests = [signed_request(auth_db.token, i, receive=slow_body) for i in range(80)]
        tasks = [asyncio.create_task(auth_db.service.require_agent_token_dep(request)) for request in requests]
        try:
            started = time.monotonic()
            for _ in range(3):
                await asyncio.sleep(.01)
            assert time.monotonic() - started < .5
            assert not waiting
            assert any(step == "execute" for step, _ in auth_db.events)
            held.close()
            await asyncio.wait_for(all_bodies_waiting.wait(), timeout=3)
            # More than the production pool's 60 requests are now paused on
            # incoming body data, yet none owns a database connection.
            assert auth_db.engine.pool.checkedout() == 0
            assert sum(step == "create" for step, _ in auth_db.events) == 80
            assert sum(step == "close" for step, _ in auth_db.events) == 80
            release_bodies.set()
            await asyncio.gather(*tasks)
            assert all(request.state.agent_auth_kind == "per_agent" for request in requests)
            assert all(request.state.agent_hmac_verified for request in requests)
            assert all(request.state.agent_auth_agent_id == f"node-{i:03}" for i, request in enumerate(requests))
            assert all(owner != threading.get_ident() for _, owner in auth_db.events)
        finally:
            held.close()
            release_bodies.set()
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
    asyncio.run(scenario())


@pytest.mark.parametrize("failure", ["signature", "token", "shared_runtime"])
def test_auth_failures_use_closed_worker_sessions_and_preserve_audit(auth_db, failure):
    token = auth_db.token
    signature = None
    expected_status, reason = 401, "invalid_hmac_signature"
    if failure == "signature":
        signature = "invalid"
    elif failure == "token":
        token = "revoked-or-wrong-token"
        reason = "Invalid agent token"
    else:
        token = "registration-only-token"
        expected_status, reason = 403, "shared_token_not_allowed_for_runtime"
    request = signed_request(token, signature=signature)

    with pytest.raises(HTTPException) as caught:
        asyncio.run(auth_db.service.require_agent_token_dep(request))
    assert caught.value.status_code == expected_status
    assert auth_db.engine.pool.checkedout() == 0
    assert all(owner != threading.get_ident() for _, owner in auth_db.events)
    assert sum(step == "create" for step, _ in auth_db.events) == sum(step == "close" for step, _ in auth_db.events)
    with auth_db.sessions() as db:
        event = db.execute(select(auth_db.models.AuditEvent)).scalar_one()
        assert event.action == "agent.auth.failed"
        assert event.meta == {"reason": reason, "path": "/agent/inventory/packages"}
        assert event.ip_address == "192.0.2.1"


def test_cancelled_auth_joins_lookup_and_releases_connection(auth_db):
    async def scenario():
        held = auth_db.engine.connect()
        task = asyncio.create_task(auth_db.service.require_agent_token_dep(signed_request(auth_db.token)))
        try:
            for _ in range(100):
                if any(step == "execute" for step, _ in auth_db.events):
                    break
                await asyncio.sleep(.01)
            assert any(step == "execute" for step, _ in auth_db.events)
            task.cancel()
            await asyncio.sleep(.01)
            assert not task.done()
            held.close()
            with pytest.raises(asyncio.CancelledError):
                await asyncio.wait_for(task, timeout=2)
            assert auth_db.engine.pool.checkedout() == 0
            assert [step for step, _ in auth_db.events] == ["create", "execute", "close"]
        finally:
            held.close()
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
    asyncio.run(scenario())
