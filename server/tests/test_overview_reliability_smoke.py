import importlib
from datetime import datetime, timedelta, timezone


def test_overview_and_cron_smoke_sqlite(monkeypatch):
    # Configure environment before importing app modules.
    monkeypatch.setenv("DATABASE_URL", "sqlite+pysqlite:///:memory:")
    monkeypatch.setenv("BOOTSTRAP_USERNAME", "admin")
    monkeypatch.setenv("BOOTSTRAP_PASSWORD", "admin-password-123")
    monkeypatch.setenv("UI_COOKIE_SECURE", "false")
    monkeypatch.setenv("ALLOW_INSECURE_NO_AGENT_TOKEN", "true")
    monkeypatch.setenv("MFA_REQUIRE_FOR_PRIVILEGED", "false")

    app_factory = importlib.import_module("app.app_factory")
    app = app_factory.create_app()

    from fastapi.testclient import TestClient

    with TestClient(app) as client:
        # Seed one host through agent register so host-dependent endpoints have data.
        r = client.post(
            "/agent/register",
            json={
                "agent_id": "srv-001",
                "hostname": "srv-001",
                "fqdn": None,
                "os_id": "ubuntu",
                "os_version": "24.04",
                "kernel": "test",
                "labels": {"env": "test", "role": "postgres"},
            },
        )
        assert r.status_code == 200, r.text

        # Login
        r = client.post("/auth/login", json={"username": "admin", "password": "admin-password-123"})
        assert r.status_code == 200, r.text

        csrf = client.cookies.get("fleet_csrf")
        headers = {"X-CSRF-Token": csrf} if csrf else {}

        # Dashboard summary smoke
        r = client.get("/dashboard/summary")
        assert r.status_code == 200, r.text
        d = r.json()
        assert "hosts" in d and "updates" in d and "jobs" in d

        # New notification center feed smoke
        r = client.get("/dashboard/notifications", params={"limit": 30})
        assert r.status_code == 200, r.text
        nd = r.json()
        assert "items" in nd and isinstance(nd["items"], list)

        # Failed runs endpoint smoke
        r = client.get("/dashboard/failed-runs", params={"hours": 24, "limit": 20})
        assert r.status_code == 200, r.text
        fd = r.json()
        assert "items" in fd and isinstance(fd["items"], list)

        # Cron create/list smoke
        run_at = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
        r = client.post(
            "/cronjobs",
            json={
                "name": "smoke inventory",
                "run_at": run_at,
                "action": "inventory-now",
                "agent_ids": ["srv-001"],
                "schedule_kind": "once",
                "timezone": "UTC",
            },
            headers=headers,
        )
        assert r.status_code == 200, r.text
        cron_id = r.json().get("id")
        assert cron_id

        r = client.get("/cronjobs")
        assert r.status_code == 200, r.text
        items = r.json().get("items") or []
        assert any(it.get("id") == cron_id for it in items)


def test_mfa_gate_403_is_suppressed_in_overview_js():
    from pathlib import Path

    root = Path(__file__).resolve().parents[2]
    js = (root / "server" / "app" / "templates" / "fleet-phase3-overview.js").read_text(encoding="utf-8")

    # During MFA-gated bootstrapping, 403 from protected endpoints should not show scary errors.
    assert "if (r.status === 403)" in js
    assert "Expected transient state during MFA gating" in js
    assert "if (r.status === 403) return; // MFA transient" in js
