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
    monkeypatch.setenv("MFA_REQUIRE_FOR_PRIVILEGED", "false")
    monkeypatch.setenv("AUTH_OIDC_ENABLED", "true")
    monkeypatch.setenv("AUTH_OIDC_ISSUER", "https://issuer.example")
    monkeypatch.setenv("AUTH_OIDC_CLIENT_ID", "fleet-client")
    monkeypatch.setenv("AUTH_OIDC_CLIENT_SECRET", "fleet-secret")
    monkeypatch.setenv("AUTH_OIDC_REDIRECT_URI", "http://localhost:8000/auth/oidc/callback")


class _Resp:
    def __init__(self, status_code=200, data=None):
        self.status_code = status_code
        self._data = data or {}

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"http {self.status_code}")

    def json(self):
        return self._data


def test_oidc_login_redirect_sets_state_and_nonce(monkeypatch):
    _base_env(monkeypatch)
    _reload_app_modules()

    app_factory = importlib.import_module("app.app_factory")
    app = app_factory.create_app()

    auth_mod = importlib.import_module("app.routers.auth")

    def fake_get(url, timeout=0):
        assert "/.well-known/openid-configuration" in url
        return _Resp(200, {"authorization_endpoint": "https://issuer.example/oauth2/v2/auth"})

    monkeypatch.setattr(auth_mod.httpx, "get", fake_get)

    from fastapi.testclient import TestClient

    with TestClient(app) as client:
        r = client.get("/auth/oidc/login", follow_redirects=False)
        assert r.status_code == 302
        assert "https://issuer.example/oauth2/v2/auth?" in (r.headers.get("location") or "")
        assert client.cookies.get("fleet_oidc_state")
        assert client.cookies.get("fleet_oidc_nonce")


def test_oidc_callback_provisions_user_with_role_and_scope(monkeypatch):
    _base_env(monkeypatch)
    monkeypatch.setenv("AUTH_OIDC_ALLOWED_EMAIL_DOMAINS", "example.com")
    monkeypatch.setenv("AUTH_OIDC_GROUP_ROLE_MAP", '{"fleet-ops":"operator"}')
    monkeypatch.setenv("AUTH_OIDC_GROUP_SCOPE_MAP", '{"fleet-ops":[{"env":["prod"]}]}')
    _reload_app_modules()

    app_factory = importlib.import_module("app.app_factory")
    app = app_factory.create_app()

    auth_mod = importlib.import_module("app.routers.auth")

    def fake_get(url, headers=None, timeout=0):
        if "/.well-known/openid-configuration" in url:
            return _Resp(200, {
                "authorization_endpoint": "https://issuer.example/auth",
                "token_endpoint": "https://issuer.example/token",
                "userinfo_endpoint": "https://issuer.example/userinfo",
                "jwks_uri": "https://issuer.example/jwks",
            })
        if url == "https://issuer.example/userinfo":
            return _Resp(200, {
                "sub": "sub-123",
                "email": "alice@example.com",
                "preferred_username": "alice",
                "groups": ["fleet-ops"],
            })
        raise AssertionError(f"unexpected GET {url}")

    def fake_post(url, data=None, timeout=0):
        assert url == "https://issuer.example/token"
        return _Resp(200, {"access_token": "at-123", "id_token": "id-123"})

    def fake_validate(disc, id_token, expected_nonce):
        assert id_token == "id-123"
        assert expected_nonce
        return {"sub": "sub-123", "email": "alice@example.com", "preferred_username": "alice", "nonce": expected_nonce}

    monkeypatch.setattr(auth_mod.httpx, "get", fake_get)
    monkeypatch.setattr(auth_mod.httpx, "post", fake_post)
    monkeypatch.setattr(auth_mod, "_oidc_validate_id_token", fake_validate)

    from fastapi.testclient import TestClient
    from app.db import SessionLocal
    from app.models import AppUser, AppUserScope, OIDCAuthEvent
    from sqlalchemy import select

    with TestClient(app) as client:
        # Seed state/nonce via login endpoint first.
        r = client.get("/auth/oidc/login", follow_redirects=False)
        assert r.status_code == 302
        state = client.cookies.get("fleet_oidc_state")
        assert state

        cb = client.get(f"/auth/oidc/callback?code=ok&state={state}", follow_redirects=False)
        assert cb.status_code == 302
        assert cb.headers.get("location") == "/"
        assert client.cookies.get("fleet_session")

    db = SessionLocal()
    try:
        u = db.execute(select(AppUser).where(AppUser.username == "alice")).scalar_one_or_none()
        assert u is not None
        assert u.role == "operator"

        scopes = db.execute(select(AppUserScope).where(AppUserScope.user_id == u.id)).scalars().all()
        assert len(scopes) == 1
        assert scopes[0].selector == {"env": ["prod"]}

        events = db.execute(select(OIDCAuthEvent).order_by(OIDCAuthEvent.created_at.asc())).scalars().all()
        assert len(events) >= 1
        assert any(ev.stage == "login_success" and ev.status == "success" for ev in events)
        assert all(bool(getattr(ev, "correlation_id", None)) for ev in events)
    finally:
        db.close()


def test_oidc_callback_rejects_disallowed_email_domain(monkeypatch):
    _base_env(monkeypatch)
    monkeypatch.setenv("AUTH_OIDC_ALLOWED_EMAIL_DOMAINS", "example.com")
    _reload_app_modules()

    app_factory = importlib.import_module("app.app_factory")
    app = app_factory.create_app()

    auth_mod = importlib.import_module("app.routers.auth")

    def fake_get(url, headers=None, timeout=0):
        if "/.well-known/openid-configuration" in url:
            return _Resp(200, {
                "authorization_endpoint": "https://issuer.example/auth",
                "token_endpoint": "https://issuer.example/token",
                "userinfo_endpoint": "https://issuer.example/userinfo",
                "jwks_uri": "https://issuer.example/jwks",
            })
        if url == "https://issuer.example/userinfo":
            return _Resp(200, {
                "sub": "sub-123",
                "email": "alice@other.com",
                "preferred_username": "alice",
            })
        raise AssertionError(f"unexpected GET {url}")

    def fake_post(url, data=None, timeout=0):
        return _Resp(200, {"access_token": "at-123", "id_token": "id-123"})

    monkeypatch.setattr(auth_mod.httpx, "get", fake_get)
    monkeypatch.setattr(auth_mod.httpx, "post", fake_post)
    monkeypatch.setattr(auth_mod, "_oidc_validate_id_token", lambda *a, **k: {"sub": "sub-123"})

    from fastapi.testclient import TestClient
    from app.db import SessionLocal
    from app.models import OIDCAuthEvent
    from sqlalchemy import select

    with TestClient(app) as client:
        r = client.get("/auth/oidc/login", follow_redirects=False)
        assert r.status_code == 302
        state = client.cookies.get("fleet_oidc_state")
        bad = client.get(f"/auth/oidc/callback?code=ok&state={state}")
        assert bad.status_code == 403
        assert "domain" in bad.text.lower()

    db = SessionLocal()
    try:
        events = db.execute(select(OIDCAuthEvent).order_by(OIDCAuthEvent.created_at.asc())).scalars().all()
        assert len(events) >= 1
        assert any(ev.stage == "domain_check" and ev.status == "error" for ev in events)
    finally:
        db.close()
