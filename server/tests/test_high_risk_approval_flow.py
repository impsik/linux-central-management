import importlib
import sys
from datetime import datetime, timedelta, timezone


def _reload_app_modules():
    for k in list(sys.modules.keys()):
        if k == "app" or k.startswith("app."):
            sys.modules.pop(k, None)


def test_dist_upgrade_creates_approval_request_when_enabled(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "sqlite+pysqlite:///:memory:")
    monkeypatch.setenv("BOOTSTRAP_USERNAME", "admin")
    monkeypatch.setenv("BOOTSTRAP_PASSWORD", "admin-password-123")
    monkeypatch.setenv("MFA_REQUIRE_FOR_PRIVILEGED", "false")
    monkeypatch.setenv("ALLOW_INSECURE_NO_AGENT_TOKEN", "true")
    monkeypatch.setenv("HIGH_RISK_APPROVAL_ENABLED", "true")
    monkeypatch.setenv("HIGH_RISK_APPROVAL_ACTIONS", "dist-upgrade,security-campaign")

    _reload_app_modules()
    app_factory = importlib.import_module("app.app_factory")
    app = app_factory.create_app()

    from fastapi.testclient import TestClient

    with TestClient(app) as client:
        # host needed for target resolution
        rr = client.post(
            "/agent/register",
            json={
                "agent_id": "srv-001",
                "hostname": "srv-001",
                "fqdn": None,
                "os_id": "ubuntu",
                "os_version": "24.04",
                "kernel": "test",
                "labels": {"env": "test"},
            },
        )
        assert rr.status_code == 200, rr.text

        lr = client.post("/auth/login", json={"username": "admin", "password": "admin-password-123"})
        assert lr.status_code == 200, lr.text
        csrf = client.cookies.get("fleet_csrf")
        headers = {"X-CSRF-Token": csrf} if csrf else {}

        r = client.post("/jobs/dist-upgrade", json={"agent_ids": ["srv-001"]}, headers=headers)
        assert r.status_code == 200, r.text
        d = r.json()
        assert d.get("approval_required") is True
        assert d.get("status") == "pending"
        assert d.get("request_id")

        # pending appears in admin queue
        q = client.get("/approvals/admin/pending")
        assert q.status_code == 200, q.text
        items = q.json().get("items") or []
        assert any(it.get("id") == d.get("request_id") for it in items)


def test_security_campaign_creates_approval_request_when_enabled(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "sqlite+pysqlite:///:memory:")
    monkeypatch.setenv("BOOTSTRAP_USERNAME", "admin")
    monkeypatch.setenv("BOOTSTRAP_PASSWORD", "admin-password-123")
    monkeypatch.setenv("MFA_REQUIRE_FOR_PRIVILEGED", "false")
    monkeypatch.setenv("ALLOW_INSECURE_NO_AGENT_TOKEN", "true")
    monkeypatch.setenv("HIGH_RISK_APPROVAL_ENABLED", "true")
    monkeypatch.setenv("HIGH_RISK_APPROVAL_ACTIONS", "dist-upgrade,security-campaign")

    _reload_app_modules()
    app_factory = importlib.import_module("app.app_factory")
    app = app_factory.create_app()

    from fastapi.testclient import TestClient

    with TestClient(app) as client:
        rr = client.post(
            "/agent/register",
            json={
                "agent_id": "srv-001",
                "hostname": "srv-001",
                "fqdn": None,
                "os_id": "ubuntu",
                "os_version": "24.04",
                "kernel": "test",
                "labels": {"env": "test"},
            },
        )
        assert rr.status_code == 200, rr.text

        lr = client.post("/auth/login", json={"username": "admin", "password": "admin-password-123"})
        assert lr.status_code == 200, lr.text
        csrf = client.cookies.get("fleet_csrf")
        headers = {"X-CSRF-Token": csrf} if csrf else {}

        now = datetime.now(timezone.utc)
        r = client.post(
            "/patching/campaigns/security-updates",
            json={
                "agent_ids": ["srv-001"],
                "window_start": now.isoformat(),
                "window_end": (now + timedelta(hours=1)).isoformat(),
            },
            headers=headers,
        )
        assert r.status_code == 200, r.text
        d = r.json()
        assert d.get("approval_required") is True
        assert d.get("status") == "pending"
