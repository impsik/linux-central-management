import importlib
import secrets
import sys
from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient


def _reload_app_modules():
    for name in list(sys.modules.keys()):
        if name == "app" or name.startswith("app."):
            sys.modules.pop(name, None)


def _boot_app(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "sqlite+pysqlite:///:memory:")
    monkeypatch.setenv("SERVER_BIND_HOST", "127.0.0.1")
    monkeypatch.setenv("BOOTSTRAP_USERNAME", "admin")
    monkeypatch.setenv("BOOTSTRAP_PASSWORD", "admin-password-123")
    monkeypatch.setenv("UI_COOKIE_SECURE", "false")
    monkeypatch.setenv("ALLOW_INSECURE_NO_AGENT_TOKEN", "true")
    monkeypatch.setenv("AGENT_SHARED_TOKEN", "")
    monkeypatch.setenv("AGENT_TERMINAL_TOKEN", "real-terminal-token")
    monkeypatch.setenv("DB_AUTO_CREATE_TABLES", "true")
    monkeypatch.setenv("DB_REQUIRE_MIGRATIONS_UP_TO_DATE", "false")
    monkeypatch.setenv("MFA_REQUIRE_FOR_PRIVILEGED", "false")
    _reload_app_modules()
    app_factory = importlib.import_module("app.app_factory")
    return app_factory.create_app()


def _create_session(username: str, role: str, labels: dict | None = None) -> str:
    db_mod = importlib.import_module("app.db")
    deps = importlib.import_module("app.deps")
    models = importlib.import_module("app.models")

    token = secrets.token_urlsafe(24)
    host_labels = {"owner": username}
    host_labels.update(labels or {})
    with db_mod.SessionLocal() as db:
        user = models.AppUser(username=username, password_hash="unused", role=role, is_active=True)
        db.add(user)
        db.flush()
        db.add(
            models.AppSession(
                user_id=user.id,
                token_sha256=deps.sha256_hex(token),
                expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
            )
        )
        db.add(
            models.Host(
                agent_id="srv-terminal",
                hostname="srv-terminal",
                ip_address="192.0.2.55",
                os_id="ubuntu",
                os_version="24.04",
                kernel="test",
                labels=host_labels,
                last_seen=datetime.now(timezone.utc),
            )
        )
        db.commit()
    return token


def _audit_events(action: str):
    db_mod = importlib.import_module("app.db")
    models = importlib.import_module("app.models")
    with db_mod.SessionLocal() as db:
        return db.query(models.AuditEvent).filter_by(action=action).order_by(models.AuditEvent.created_at.asc()).all()


def test_terminal_session_open_and_close_are_audited(monkeypatch):
    app = _boot_app(monkeypatch)
    terminal_ws = importlib.import_module("app.routers.terminal_ws")

    async def fake_raw_pipe(ws, agent_url, headers=None, allow_input=True):
        assert agent_url == "ws://192.0.2.55:18080/terminal/ws"
        assert headers == {"X-Fleet-Terminal-Token": "real-terminal-token"}
        assert allow_input is True
        await ws.send_text("terminal-ok")

    monkeypatch.setattr(terminal_ws, "raw_pipe", fake_raw_pipe)

    with TestClient(app) as client:
        token = _create_session("operator1", "operator")
        client.cookies.set("fleet_session", token)
        with client.websocket_connect("/ws/terminal/srv-terminal") as ws:
            assert ws.receive_text() == "terminal-ok"

    opened = _audit_events("terminal.session.opened")
    closed = _audit_events("terminal.session.closed")
    assert len(opened) == 1
    assert len(closed) == 1
    assert opened[0].actor_username == "operator1"
    assert opened[0].target_id == "srv-terminal"
    assert opened[0].meta["role"] == "operator"
    assert opened[0].meta["terminal_access"] == "all"
    assert opened[0].meta["connect_target"] == "192.0.2.55"
    assert "real-terminal-token" not in str(opened[0].meta)


def test_terminal_policy_denial_is_audited(monkeypatch):
    app = _boot_app(monkeypatch)

    with TestClient(app) as client:
        token = _create_session("operator2", "operator", labels={"terminal_access": "admin"})
        client.cookies.set("fleet_session", token)
        try:
            with client.websocket_connect("/ws/terminal/srv-terminal") as ws:
                ws.receive_text()
        except Exception:
            pass

    denied = _audit_events("terminal.session.denied")
    assert len(denied) == 1
    assert denied[0].actor_username == "operator2"
    assert denied[0].target_id == "srv-terminal"
    assert denied[0].meta["role"] == "operator"
    assert denied[0].meta["terminal_access"] == "admin"
    assert denied[0].meta["reason"] == "terminal_access_admin"


def test_terminal_pipe_error_is_audited_without_secrets(monkeypatch):
    app = _boot_app(monkeypatch)
    terminal_ws = importlib.import_module("app.routers.terminal_ws")

    async def failing_raw_pipe(ws, agent_url, headers=None, allow_input=True):
        raise RuntimeError("agent terminal exploded")

    monkeypatch.setattr(terminal_ws, "raw_pipe", failing_raw_pipe)

    with TestClient(app) as client:
        token = _create_session("operator3", "operator")
        client.cookies.set("fleet_session", token)
        try:
            with client.websocket_connect("/ws/terminal/srv-terminal") as ws:
                ws.receive_text()
        except Exception:
            pass

    errors = _audit_events("terminal.session.error")
    assert len(errors) == 1
    assert errors[0].actor_username == "operator3"
    assert errors[0].target_id == "srv-terminal"
    assert errors[0].meta["role"] == "operator"
    assert errors[0].meta["reason"] == "RuntimeError"
    assert errors[0].meta["connect_target"] == "192.0.2.55"
    assert "real-terminal-token" not in str(errors[0].meta)
