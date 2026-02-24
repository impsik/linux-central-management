import importlib


def test_audit_timeline_includes_normalized_events(monkeypatch):
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

    from app.db import SessionLocal
    from app.models import OIDCAuthEvent
    from fastapi.testclient import TestClient

    with TestClient(app) as client:
        # login as admin
        r = client.post("/auth/login", json={"username": "admin", "password": "admin-password-123"})
        assert r.status_code == 200, r.text

        # seed one OIDC event directly
        db = SessionLocal()
        try:
            db.add(
                OIDCAuthEvent(
                    provider="https://issuer.example",
                    stage="token_exchange",
                    status="error",
                    error_code="token_exchange_failed",
                    error_message="bad secret",
                    correlation_id="corr-xyz",
                    username="alice",
                )
            )
            db.commit()
        finally:
            db.close()

        # create an audit event by calling admin users endpoint
        users = client.get("/auth/admin/users")
        assert users.status_code == 200, users.text

        tl = client.get("/audit/timeline", params={"limit": 50})
        assert tl.status_code == 200, tl.text
        data = tl.json()
        assert data["total"] >= 1
        assert isinstance(data["items"], list)
        assert any(it.get("source") == "oidc_auth_events" for it in data["items"])
        assert any(it.get("source") == "audit_events" for it in data["items"])
        sample = data["items"][0]
        assert "actor" in sample and "target" in sample and "result" in sample and "metadata" in sample
