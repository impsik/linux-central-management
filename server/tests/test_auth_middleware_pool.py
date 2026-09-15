import asyncio
from datetime import datetime, timedelta, timezone
import sys
import threading

import pytest
from sqlalchemy import create_engine, event, select
from sqlalchemy.orm import sessionmaker
from starlette.requests import Request
from starlette.responses import JSONResponse


@pytest.fixture
def auth_stack(monkeypatch, tmp_path):
    saved = {name: module for name, module in sys.modules.copy().items()
             if name == "app" or name.startswith("app.")}
    for name in saved:
        sys.modules.pop(name)
    monkeypatch.setenv("DATABASE_URL", "sqlite+pysqlite:///:memory:")
    monkeypatch.setenv("UI_COOKIE_SECURE", "false")
    engine = None
    try:
        from app import app_factory, models
        from app.config import settings
        from app.deps import sha256_hex

        engine = create_engine(f"sqlite:///{tmp_path / 'auth.sqlite'}",
            connect_args={"check_same_thread": False}, pool_size=1, max_overflow=0, pool_timeout=0.5)
        models.AppUser.metadata.create_all(engine, tables=[models.AppUser.__table__, models.AppSession.__table__])
        sessions = sessionmaker(bind=engine)
        monkeypatch.setattr(app_factory, "SessionLocal", sessions)
        monkeypatch.setattr(settings, "mfa_require_for_privileged", True)
        monkeypatch.setattr(settings, "ui_session_idle_minutes", 60)
        now = datetime.now(timezone.utc)
        with sessions.begin() as db:
            for token, role, enrolled, verified, active, expired in [
                ("ready", "admin", True, True, True, False),
                ("readonly", "readonly", False, False, True, False),
                ("unenrolled", "operator", False, False, True, False),
                ("unverified", "admin", True, False, True, False),
                ("inactive", "admin", True, True, False, False),
                ("expired", "admin", True, True, True, True),
            ]:
                user = models.AppUser(username=token, password_hash="unused", role=role,
                                     mfa_enabled=enrolled, is_active=active)
                db.add(user)
                db.flush()
                db.add(models.AppSession(user_id=user.id, token_sha256=sha256_hex(token),
                    expires_at=now + timedelta(minutes=-1 if expired else 30),
                    mfa_verified_at=now if verified else None))
        app = app_factory.create_app()
        dispatch = {item.kwargs["dispatch"].__name__: item.kwargs["dispatch"]
                    for item in app.user_middleware if "dispatch" in item.kwargs}
        yield app_factory, engine, sessions, dispatch
    finally:
        if engine is not None:
            engine.dispose()
        for name in list(sys.modules):
            if name == "app" or name.startswith("app."):
                sys.modules.pop(name)
        sys.modules.update(saved)


def request_for(path="/protected", *, token="ready", method="GET", csrf_header=None):
    headers = []
    if token is not None:
        headers.append((b"cookie", f"fleet_session={token}; fleet_csrf=existing-csrf".encode()))
    if csrf_header is not None:
        headers.append((b"x-csrf-token", csrf_header.encode()))
    return Request({"type": "http", "method": method, "scheme": "https", "path": path,
                    "root_path": "", "query_string": b"", "server": ("fleet.test", 443), "headers": headers})


async def success(request):
    return JSONResponse({"ok": True})


def test_auth_releases_its_only_pool_connection_before_downstream_await(auth_stack):
    _, engine, sessions, dispatch = auth_stack
    downstream_called = []

    async def downstream(request):
        assert engine.pool.checkedout() == 0
        # A downstream handler can acquire the same one-connection pool.
        with sessions() as db:
            assert db.scalar(select(1)) == 1
        await asyncio.sleep(0)
        downstream_called.append(True)
        return JSONResponse({"ok": True})

    response = asyncio.run(dispatch["auth_middleware"](request_for(), downstream))

    assert response.status_code == 200
    assert downstream_called == [True]
    assert engine.pool.checkedout() == 0


def test_auth_database_wait_does_not_block_event_loop(auth_stack):
    _, engine, _, dispatch = auth_stack
    release = threading.Event()
    worker_threads = []

    async def exercise():
        loop = asyncio.get_running_loop()
        started = asyncio.Event()

        def hold_query(conn, cursor, statement, parameters, context, executemany):
            worker_threads.append(threading.get_ident())
            loop.call_soon_threadsafe(started.set)
            assert release.wait(2), "auth SQL blocked the event loop"

        event.listen(engine, "before_cursor_execute", hold_query)
        task = asyncio.create_task(dispatch["auth_middleware"](request_for(), success))
        try:
            await asyncio.wait_for(started.wait(), timeout=1)
            assert len(worker_threads) == 1
            assert worker_threads[0] != threading.get_ident()
            release.set()
            assert (await task).status_code == 200
        finally:
            release.set()
            await asyncio.gather(task, return_exceptions=True)
            event.remove(engine, "before_cursor_execute", hold_query)

    asyncio.run(exercise())


@pytest.mark.parametrize(("path", "token", "status", "detail"), [
    ("/", None, 302, None),
    ("/protected", None, 401, "Not authenticated"),
    ("/protected", "unknown", 401, "Not authenticated"),
    ("/protected", "expired", 401, "Not authenticated"),
    ("/protected", "inactive", 401, "Not authenticated"),
    ("/protected", "unenrolled", 403, "MFA enrollment required"),
    ("/protected", "unverified", 403, "MFA verification required"),
    ("/protected", "ready", 200, None),
    ("/protected", "readonly", 200, None),
    ("/", "unenrolled", 200, None),
    ("/terminal", "unenrolled", 200, None),
    ("/shell.css", "unenrolled", 200, None),
])
def test_auth_denials_and_mfa_shell_exemptions_remain(auth_stack, path, token, status, detail):
    _, engine, _, dispatch = auth_stack
    response = asyncio.run(dispatch["auth_middleware"](request_for(path, token=token), success))

    assert response.status_code == status
    assert engine.pool.checkedout() == 0
    if detail:
        import json
        assert json.loads(response.body) == {"detail": detail}
        assert "set-cookie" not in response.headers
    if status == 302:
        assert response.headers["location"] == "/login"
    if token == "unenrolled" and status == 200:
        assert "set-cookie" not in response.headers


@pytest.mark.parametrize("path", ["/agent/heartbeat", "/patching/cve/CVE-2026-1234", "/health",
    "/auth/me", "/login", "/assets/shell.js", "/static/logo.png", "/ws/terminal"])
def test_existing_unauthenticated_bypasses_do_not_open_sessions(auth_stack, monkeypatch, path):
    factory, _, _, dispatch = auth_stack
    monkeypatch.setattr(factory, "SessionLocal", lambda: pytest.fail("bypass opened a DB session"))

    response = asyncio.run(dispatch["auth_middleware"](request_for(path, token=None), success))

    assert response.status_code == 200
    assert "set-cookie" not in response.headers


def test_cookie_refresh_preserves_csrf_absolute_expiry_and_https_security(auth_stack, monkeypatch):
    from http.cookies import SimpleCookie

    _, _, _, dispatch = auth_stack
    monkeypatch.delenv("UI_COOKIE_SECURE", raising=False)
    response = asyncio.run(dispatch["auth_middleware"](request_for(), success))
    cookies = SimpleCookie()
    for header in response.headers.getlist("set-cookie"):
        cookies.load(header)

    assert cookies["fleet_session"].value == "ready"
    assert cookies["fleet_session"]["httponly"]
    assert cookies["fleet_session"]["secure"]
    assert 1700 <= int(cookies["fleet_session"]["max-age"]) <= 1800
    assert cookies["fleet_csrf"].value == "existing-csrf"
    assert not cookies["fleet_csrf"]["httponly"]
    assert cookies["fleet_csrf"]["secure"]


@pytest.mark.parametrize("csrf_header", [None, "wrong", "existing-csrf"])
def test_csrf_middleware_still_gates_authenticated_writes(auth_stack, csrf_header):
    _, _, _, dispatch = auth_stack

    async def auth(request):
        return await dispatch["auth_middleware"](request, success)

    request = request_for(method="POST", csrf_header=csrf_header)
    response = asyncio.run(dispatch["csrf_middleware"](request, auth))
    assert response.status_code == (200 if csrf_header == "existing-csrf" else 403)
