import importlib


def test_admin_rbac_explain_allow_and_deny(monkeypatch):
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
    app = app_factory.create_app()

    from fastapi.testclient import TestClient
    from sqlalchemy import select
    from app.db import SessionLocal
    from app.models import AppUser, Host

    with TestClient(app) as client:
        # seed hosts
        r = client.post(
            "/agent/register",
            json={
                "agent_id": "srv-prod",
                "hostname": "srv-prod",
                "os_id": "ubuntu",
                "os_version": "22.04",
                "kernel": "test",
                "labels": {"env": "prod", "team": "core"},
            },
        )
        assert r.status_code == 200, r.text

        r = client.post(
            "/agent/register",
            json={
                "agent_id": "srv-dev",
                "hostname": "srv-dev",
                "os_id": "ubuntu",
                "os_version": "22.04",
                "kernel": "test",
                "labels": {"env": "dev", "team": "core"},
            },
        )
        assert r.status_code == 200, r.text

        # admin login
        r = client.post("/auth/login", json={"username": "admin", "password": "admin-password-123"})
        assert r.status_code == 200, r.text
        csrf = client.cookies.get("fleet_csrf")
        headers = {"X-CSRF-Token": csrf} if csrf else {}

        # create test user
        reg = client.post("/auth/register", json={"username": "op1", "password": "pw-123456"}, headers=headers)
        assert reg.status_code == 200, reg.text

        # set scoped selector env=prod
        set_scope = client.post(
            "/auth/admin/users/op1/scopes",
            json={"selectors": [{"env": ["prod"]}]},
            headers=headers,
        )
        assert set_scope.status_code == 200, set_scope.text

        db = SessionLocal()
        try:
            user = db.execute(select(AppUser).where(AppUser.username == "op1")).scalar_one()
            host_prod = db.execute(select(Host).where(Host.agent_id == "srv-prod")).scalar_one()
            host_dev = db.execute(select(Host).where(Host.agent_id == "srv-dev")).scalar_one()
        finally:
            db.close()

        allow = client.get(
            "/auth/admin/rbac/explain",
            params={"user_id": str(user.id), "host_id": str(host_prod.id)},
            headers=headers,
        )
        assert allow.status_code == 200, allow.text
        ad = allow.json()
        assert ad["allowed"] is True
        assert ad["user"]["username"] == "op1"
        assert ad["host"]["agent_id"] == "srv-prod"

        deny = client.get(
            "/auth/admin/rbac/explain",
            params={"user_id": str(user.id), "host_id": str(host_dev.id)},
            headers=headers,
        )
        assert deny.status_code == 200, deny.text
        dd = deny.json()
        assert dd["allowed"] is False
        assert "selector_results" in dd["scopes"]
        assert any(not it.get("matched") for it in dd["scopes"]["selector_results"])
