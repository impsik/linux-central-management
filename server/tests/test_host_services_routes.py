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


def test_service_control_route_exists_and_returns_host_not_found(monkeypatch):
    app = _boot_app(monkeypatch)

    from fastapi.testclient import TestClient

    with TestClient(app) as client:
        r = client.post("/auth/login", json={"username": "admin", "password": "admin-password-123"})
        assert r.status_code == 200, r.text

        csrf = client.cookies.get("fleet_csrf")
        headers = {"X-CSRF-Token": csrf} if csrf else {}

        resp = client.post("/hosts/nonexistent-agent/services/ssh/restart", headers=headers)
        assert resp.status_code == 404, resp.text
        assert resp.json().get("detail") == "Host not found"
