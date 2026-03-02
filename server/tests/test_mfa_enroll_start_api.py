import importlib
import sys


def _reload_app_modules():
    for k in list(sys.modules.keys()):
        if k == "app" or k.startswith("app."):
            sys.modules.pop(k, None)


def _base_env(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "sqlite+pysqlite:///:memory:")
    monkeypatch.setenv("BOOTSTRAP_USERNAME", "admin")
    monkeypatch.setenv("BOOTSTRAP_PASSWORD", "admin-password-123")
    monkeypatch.setenv("UI_COOKIE_SECURE", "false")
    monkeypatch.setenv("ALLOW_INSECURE_NO_AGENT_TOKEN", "true")
    monkeypatch.setenv("AGENT_SHARED_TOKEN", "")
    monkeypatch.setenv("DB_AUTO_CREATE_TABLES", "true")
    monkeypatch.setenv("DB_REQUIRE_MIGRATIONS_UP_TO_DATE", "false")
    monkeypatch.setenv("MFA_REQUIRE_FOR_PRIVILEGED", "true")


def _login(client):
    r = client.post("/auth/login", json={"username": "admin", "password": "admin-password-123"})
    assert r.status_code == 200
    csrf = client.cookies.get("fleet_csrf")
    assert csrf
    return csrf


def test_mfa_enroll_start_accepts_quoted_fernet_key(monkeypatch):
    _base_env(monkeypatch)

    # Real key wrapped in quotes (common .env misconfiguration).
    raw = "_rNr8yrCmiYQ9pGyQQlAWx-IvRfb8v-X8IG4MvfFcRo="
    monkeypatch.setenv("MFA_ENCRYPTION_KEY", f'"{raw}"')

    _reload_app_modules()
    app_factory = importlib.import_module("app.app_factory")
    app = app_factory.create_app()

    from fastapi.testclient import TestClient

    with TestClient(app) as client:
        csrf = _login(client)
        r = client.post(
            "/auth/mfa/enroll/start",
            json={},
            headers={"X-CSRF-Token": csrf},
        )
        assert r.status_code == 200, r.text
        data = r.json()
        assert data.get("ok") is True
        assert isinstance(data.get("otpauth_uri"), str) and data["otpauth_uri"].startswith("otpauth://")


def test_mfa_enroll_start_returns_actionable_error_for_invalid_key(monkeypatch):
    _base_env(monkeypatch)
    monkeypatch.setenv("MFA_ENCRYPTION_KEY", "definitely-not-a-fernet-key")

    _reload_app_modules()
    app_factory = importlib.import_module("app.app_factory")
    app = app_factory.create_app()

    from fastapi.testclient import TestClient

    with TestClient(app) as client:
        csrf = _login(client)
        r = client.post(
            "/auth/mfa/enroll/start",
            json={},
            headers={"X-CSRF-Token": csrf},
        )
        assert r.status_code == 500
        assert "MFA_ENCRYPTION_KEY is invalid" in (r.text or "")
