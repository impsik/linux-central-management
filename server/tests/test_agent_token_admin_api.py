import importlib
import sys


def _reload_app_modules():
    for name in list(sys.modules.keys()):
        if name == "app" or name.startswith("app."):
            sys.modules.pop(name, None)


def _boot_app(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "sqlite+pysqlite:///:memory:")
    monkeypatch.setenv("BOOTSTRAP_USERNAME", "admin")
    monkeypatch.setenv("BOOTSTRAP_PASSWORD", "admin-password-123")
    monkeypatch.setenv("UI_COOKIE_SECURE", "false")
    monkeypatch.setenv("ALLOW_INSECURE_NO_AGENT_TOKEN", "true")
    monkeypatch.setenv("AGENT_SHARED_TOKEN", "")
    monkeypatch.setenv("DB_AUTO_CREATE_TABLES", "true")
    monkeypatch.setenv("DB_REQUIRE_MIGRATIONS_UP_TO_DATE", "false")
    monkeypatch.setenv("MFA_REQUIRE_FOR_PRIVILEGED", "false")
    _reload_app_modules()
    app_factory = importlib.import_module("app.app_factory")
    return app_factory.create_app()


def _login(client):
    r = client.post("/auth/login", json={"username": "admin", "password": "admin-password-123"})
    assert r.status_code == 200, r.text
    csrf = client.cookies.get("fleet_csrf")
    return {"X-CSRF-Token": csrf} if csrf else {}


def _seed_host(agent_id="srv-token-admin"):
    db_mod = importlib.import_module("app.db")
    models = importlib.import_module("app.models")
    agent_auth = importlib.import_module("app.services.agent_auth")
    with db_mod.SessionLocal() as db:
        db.add(
            models.Host(
                agent_id=agent_id,
                hostname=agent_id,
                labels={},
                agent_token_hash=agent_auth.hash_agent_token("old-token"),
            )
        )
        db.commit()


def test_admin_can_rotate_agent_token(monkeypatch):
    app = _boot_app(monkeypatch)

    from fastapi.testclient import TestClient

    with TestClient(app) as client:
        _seed_host()
        headers = _login(client)
        resp = client.post("/hosts/srv-token-admin/agent-token/rotate", headers=headers)
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["ok"] is True
        assert body["agent_id"] == "srv-token-admin"
        assert body["agent_token"]
        assert body["agent_token"] != "old-token"
        assert body["token_file"] == "/var/lib/fleet-agent/agent-token"

        db_mod = importlib.import_module("app.db")
        models = importlib.import_module("app.models")
        agent_auth = importlib.import_module("app.services.agent_auth")
        with db_mod.SessionLocal() as db:
            host = db.query(models.Host).filter_by(agent_id="srv-token-admin").one()
            assert host.agent_token_hash == agent_auth.hash_agent_token(body["agent_token"])
            event = db.query(models.AuditEvent).filter_by(action="agent.token.rotated").one()
            assert event.target_id == "srv-token-admin"
            assert event.actor_username == "admin"


def test_admin_can_reset_agent_token_for_bootstrap(monkeypatch):
    app = _boot_app(monkeypatch)

    from fastapi.testclient import TestClient

    with TestClient(app) as client:
        _seed_host("srv-reset")
        headers = _login(client)
        resp = client.post("/hosts/srv-reset/agent-token/bootstrap-reset", headers=headers)
        assert resp.status_code == 200, resp.text
        assert resp.json() == {"ok": True, "agent_id": "srv-reset"}

        db_mod = importlib.import_module("app.db")
        models = importlib.import_module("app.models")
        with db_mod.SessionLocal() as db:
            host = db.query(models.Host).filter_by(agent_id="srv-reset").one()
            assert host.agent_token_hash is None
            event = db.query(models.AuditEvent).filter_by(action="agent.token.bootstrap_reset").one()
            assert event.target_id == "srv-reset"
            assert event.actor_username == "admin"
