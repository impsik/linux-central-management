import importlib

from conftest import bootstrap_test_app, login_test_client


def test_audit_timeline_includes_normalized_events(monkeypatch):
    app = bootstrap_test_app(monkeypatch)

    from app.db import SessionLocal
    from app.models import OIDCAuthEvent
    from fastapi.testclient import TestClient

    with TestClient(app) as client:
        # login as admin
        login_test_client(client)

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
