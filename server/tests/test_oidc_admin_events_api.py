import importlib
import sys
from datetime import datetime, timezone


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


def test_admin_oidc_events_list_filters(monkeypatch):
    _base_env(monkeypatch)
    _reload_app_modules()

    app_factory = importlib.import_module("app.app_factory")
    app = app_factory.create_app()

    from fastapi.testclient import TestClient
    from app.db import SessionLocal
    from app.models import OIDCAuthEvent

    with TestClient(app) as client:
        # Startup runs when TestClient context opens, ensuring tables exist.
        db = SessionLocal()
        try:
            db.add(
                OIDCAuthEvent(
                    provider="https://issuer.example",
                    stage="token_exchange",
                    status="error",
                    error_code="token_exchange_failed",
                    error_message="bad client secret",
                    correlation_id="corr-1",
                    created_at=datetime.now(timezone.utc),
                )
            )
            db.add(
                OIDCAuthEvent(
                    provider="https://issuer.example",
                    stage="login_success",
                    status="success",
                    correlation_id="corr-2",
                    username="alice",
                    created_at=datetime.now(timezone.utc),
                )
            )
            db.commit()
        finally:
            db.close()
        r = client.post("/auth/login", json={"username": "admin", "password": "admin-password-123"})
        assert r.status_code == 200, r.text
        csrf = client.cookies.get("fleet_csrf")
        headers = {"X-CSRF-Token": csrf} if csrf else {}

        all_resp = client.get("/auth/admin/oidc/events", headers=headers)
        assert all_resp.status_code == 200, all_resp.text
        all_data = all_resp.json()
        assert all_data["total"] >= 2
        assert any(it["stage"] == "token_exchange" for it in all_data["items"])

        filt = client.get(
            "/auth/admin/oidc/events",
            params={"status": "error", "stage": "token_exchange"},
            headers=headers,
        )
        assert filt.status_code == 200, filt.text
        data = filt.json()
        assert data["total"] >= 1
        assert all(it["status"] == "error" for it in data["items"])
        assert all(it["stage"] == "token_exchange" for it in data["items"])
        assert any((it.get("remediation_hint") or "").lower().startswith("check client_id") for it in data["items"])
