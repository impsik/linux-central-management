import importlib


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

    app_factory = importlib.import_module("app.app_factory")
    return app_factory.create_app()


def _seed_host(agent_id="agent-1", hostname="old-host", labels=None):
    db_mod = importlib.import_module("app.db")
    models = importlib.import_module("app.models")
    labels = labels if labels is not None else {"team": "core"}
    with db_mod.SessionLocal() as db:
        db.add(models.Host(agent_id=agent_id, hostname=hostname, labels=labels))
        db.commit()


def _login(client):
    r = client.post("/auth/login", json={"username": "admin", "password": "admin-password-123"})
    assert r.status_code == 200, r.text
    csrf = client.cookies.get("fleet_csrf")
    return {"X-CSRF-Token": csrf} if csrf else {}


def test_update_host_metadata_name_role_env_and_preserve_existing(monkeypatch):
    app = _boot_app(monkeypatch)
    _seed_host(labels={"team": "core", "role": "old"})

    from fastapi.testclient import TestClient

    with TestClient(app) as client:
        headers = _login(client)
        resp = client.patch(
            "/hosts/agent-1/metadata",
            json={
                "hostname": "new-host",
                "role": "web",
                "env": {"FOO": "bar", "X": "1"},
            },
            headers=headers,
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["ok"] is True
        assert body["host"]["hostname"] == "new-host"
        assert body["host"]["labels"]["role"] == "web"
        assert body["host"]["labels"]["team"] == "core"
        assert body["host"]["labels"]["env_vars"] == {"FOO": "bar", "X": "1"}


def test_update_host_metadata_role_when_missing_and_env_merge_idempotent(monkeypatch):
    app = _boot_app(monkeypatch)
    _seed_host(labels={"team": "ops", "env_vars": {"FOO": "old", "UNCHANGED": "yes"}})

    from fastapi.testclient import TestClient

    with TestClient(app) as client:
        headers = _login(client)
        payload = {"role": "db", "env": {"FOO": "new", "BAR": "2"}}
        first = client.patch("/hosts/agent-1/metadata", json=payload, headers=headers)
        assert first.status_code == 200, first.text
        second = client.patch("/hosts/agent-1/metadata", json=payload, headers=headers)
        assert second.status_code == 200, second.text

        labels = second.json()["host"]["labels"]
        assert labels["role"] == "db"
        assert labels["team"] == "ops"
        assert labels["env_vars"] == {"FOO": "new", "UNCHANGED": "yes", "BAR": "2"}
