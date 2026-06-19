import importlib
import sys


def _reload_app_modules():
    for k in list(sys.modules.keys()):
        if k == "app" or k.startswith("app."):
            sys.modules.pop(k, None)


def _base_env(monkeypatch):
    from cryptography.fernet import Fernet

    monkeypatch.setenv("DATABASE_URL", "sqlite+pysqlite:///:memory:")
    monkeypatch.setenv("BOOTSTRAP_USERNAME", "admin")
    monkeypatch.setenv("BOOTSTRAP_PASSWORD", "admin-password-123")
    monkeypatch.setenv("UI_COOKIE_SECURE", "false")
    monkeypatch.setenv("ALLOW_INSECURE_NO_AGENT_TOKEN", "true")
    monkeypatch.setenv("AGENT_SHARED_TOKEN", "")
    monkeypatch.setenv("DB_AUTO_CREATE_TABLES", "true")
    monkeypatch.setenv("DB_REQUIRE_MIGRATIONS_UP_TO_DATE", "false")
    monkeypatch.setenv("MFA_REQUIRE_FOR_PRIVILEGED", "false")
    monkeypatch.setenv("MFA_ENCRYPTION_KEY", Fernet.generate_key().decode("utf-8"))


def _login_admin(client):
    r = client.post("/auth/login", json={"username": "admin", "password": "admin-password-123"})
    assert r.status_code == 200, r.text
    csrf = client.cookies.get("fleet_csrf") or ""
    return {"X-CSRF-Token": csrf}


def test_admin_can_save_ad_settings_without_exposing_bind_password(monkeypatch):
    _base_env(monkeypatch)
    _reload_app_modules()

    app = importlib.import_module("app.app_factory").create_app()

    from fastapi.testclient import TestClient

    with TestClient(app) as client:
        headers = _login_admin(client)
        r = client.post(
            "/auth/admin/ad-settings",
            headers=headers,
            json={
                "enabled": True,
                "server_uri": "ldaps://dc.example.local:636",
                "domain": "example.local",
                "base_dn": "DC=example,DC=local",
                "bind_dn": "CN=fleet-bind,DC=example,DC=local",
                "bind_password": "secret-bind-password",
                "user_filter": "(sAMAccountName={username})",
                "use_ssl": True,
                "role": "operator",
            },
        )
        assert r.status_code == 200, r.text
        assert r.json()["enabled"] is True
        assert r.json()["bind_password_set"] is True

        got = client.get("/auth/admin/ad-settings")
        assert got.status_code == 200, got.text
        data = got.json()
        assert data["enabled"] is True
        assert data["bind_password_set"] is True
        assert "secret-bind-password" not in got.text


def test_ad_login_auto_creates_operator_user(monkeypatch):
    _base_env(monkeypatch)
    _reload_app_modules()

    app = importlib.import_module("app.app_factory").create_app()
    auth_mod = importlib.import_module("app.routers.auth")
    ad_mod = importlib.import_module("app.services.ad_auth")

    def fake_authenticate_ad(row, username, password):
        assert row.ad_enabled is True
        assert username == "alice"
        assert password == "alice-password"
        return ad_mod.ADAuthResult(username="alice", display_name="Alice Example", email="alice@example.local")

    monkeypatch.setattr(auth_mod, "authenticate_ad", fake_authenticate_ad)

    from app.db import SessionLocal
    from app.models import AppUser
    from fastapi.testclient import TestClient
    from sqlalchemy import select

    with TestClient(app) as client:
        headers = _login_admin(client)
        r = client.post(
            "/auth/admin/ad-settings",
            headers=headers,
            json={
                "enabled": True,
                "server_uri": "ldaps://dc.example.local:636",
                "domain": "example.local",
                "base_dn": "DC=example,DC=local",
                "bind_dn": "CN=fleet-bind,DC=example,DC=local",
                "bind_password": "secret-bind-password",
                "user_filter": "(sAMAccountName={username})",
                "use_ssl": True,
                "role": "operator",
            },
        )
        assert r.status_code == 200, r.text

        ad = client.post("/auth/ad/login", json={"username": "alice", "password": "alice-password"})
        assert ad.status_code == 200, ad.text

    with SessionLocal() as db:
        user = db.execute(select(AppUser).where(AppUser.username == "alice")).scalar_one()
        assert user.auth_provider == "ad"
        assert user.role == "operator"
        assert user.is_active is True


def test_ad_login_does_not_take_over_local_user(monkeypatch):
    _base_env(monkeypatch)
    _reload_app_modules()

    app = importlib.import_module("app.app_factory").create_app()
    auth_mod = importlib.import_module("app.routers.auth")
    ad_mod = importlib.import_module("app.services.ad_auth")

    monkeypatch.setattr(
        auth_mod,
        "authenticate_ad",
        lambda row, username, password: ad_mod.ADAuthResult(username="admin"),
    )

    from fastapi.testclient import TestClient

    with TestClient(app) as client:
        headers = _login_admin(client)
        r = client.post(
            "/auth/admin/ad-settings",
            headers=headers,
            json={
                "enabled": True,
                "server_uri": "ldaps://dc.example.local:636",
                "domain": "example.local",
                "base_dn": "DC=example,DC=local",
                "bind_dn": "CN=fleet-bind,DC=example,DC=local",
                "bind_password": "secret-bind-password",
                "user_filter": "(sAMAccountName={username})",
                "use_ssl": True,
                "role": "operator",
            },
        )
        assert r.status_code == 200, r.text

        takeover = client.post("/auth/ad/login", json={"username": "admin", "password": "any"})
        assert takeover.status_code == 409
        assert "existing local user" in takeover.text
