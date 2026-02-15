import importlib
import sys
from datetime import datetime, timedelta, timezone


def _reload_app_modules():
    for k in list(sys.modules.keys()):
        if k == "app" or k.startswith("app."):
            sys.modules.pop(k, None)


def _future_hhmm(hours_ahead: int) -> str:
    d = datetime.now(timezone.utc) + timedelta(hours=hours_ahead)
    return f"{d.hour:02d}:{d.minute:02d}"


def test_guardrails_block_dist_upgrade_outside_window(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "sqlite+pysqlite:///:memory:")
    monkeypatch.setenv("BOOTSTRAP_USERNAME", "admin")
    monkeypatch.setenv("BOOTSTRAP_PASSWORD", "admin-password-123")
    monkeypatch.setenv("MFA_REQUIRE_FOR_PRIVILEGED", "false")
    monkeypatch.setenv("ALLOW_INSECURE_NO_AGENT_TOKEN", "true")
    monkeypatch.setenv("MAINTENANCE_WINDOW_ENABLED", "true")
    monkeypatch.setenv("MAINTENANCE_WINDOW_TIMEZONE", "UTC")
    # Define a future window unlikely to include current time.
    monkeypatch.setenv("MAINTENANCE_WINDOW_START_HHMM", _future_hhmm(2))
    monkeypatch.setenv("MAINTENANCE_WINDOW_END_HHMM", _future_hhmm(3))
    monkeypatch.setenv("MAINTENANCE_WINDOW_GUARDED_ACTIONS", "dist-upgrade,security-campaign")

    _reload_app_modules()
    app_factory = importlib.import_module("app.app_factory")
    app = app_factory.create_app()

    from fastapi.testclient import TestClient

    with TestClient(app) as client:
        lr = client.post("/auth/login", json={"username": "admin", "password": "admin-password-123"})
        assert lr.status_code == 200, lr.text
        csrf = client.cookies.get("fleet_csrf")
        headers = {"X-CSRF-Token": csrf} if csrf else {}

        r = client.post("/jobs/dist-upgrade", json={"agent_ids": ["srv-001"]}, headers=headers)
        assert r.status_code == 403, r.text
        assert "maintenance window" in r.text.lower()


def test_guardrails_block_security_campaign_outside_window(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "sqlite+pysqlite:///:memory:")
    monkeypatch.setenv("BOOTSTRAP_USERNAME", "admin")
    monkeypatch.setenv("BOOTSTRAP_PASSWORD", "admin-password-123")
    monkeypatch.setenv("MFA_REQUIRE_FOR_PRIVILEGED", "false")
    monkeypatch.setenv("ALLOW_INSECURE_NO_AGENT_TOKEN", "true")
    monkeypatch.setenv("MAINTENANCE_WINDOW_ENABLED", "true")
    monkeypatch.setenv("MAINTENANCE_WINDOW_TIMEZONE", "UTC")
    monkeypatch.setenv("MAINTENANCE_WINDOW_START_HHMM", _future_hhmm(2))
    monkeypatch.setenv("MAINTENANCE_WINDOW_END_HHMM", _future_hhmm(3))
    monkeypatch.setenv("MAINTENANCE_WINDOW_GUARDED_ACTIONS", "dist-upgrade,security-campaign")

    _reload_app_modules()
    app_factory = importlib.import_module("app.app_factory")
    app = app_factory.create_app()

    from fastapi.testclient import TestClient

    with TestClient(app) as client:
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
        assert r.status_code == 403, r.text
        assert "maintenance window" in r.text.lower()
