import importlib
import sys
from datetime import datetime, timedelta, timezone

from sqlalchemy import select


def _reload_app_modules():
    for k in list(sys.modules.keys()):
        if k == "app" or k.startswith("app."):
            sys.modules.pop(k, None)


def test_notifications_dedupe_cooldown_suppresses_repeat(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "sqlite+pysqlite:///:memory:")
    monkeypatch.setenv("BOOTSTRAP_USERNAME", "admin")
    monkeypatch.setenv("BOOTSTRAP_PASSWORD", "admin-password-123")
    monkeypatch.setenv("MFA_REQUIRE_FOR_PRIVILEGED", "false")
    monkeypatch.setenv("ALLOW_INSECURE_NO_AGENT_TOKEN", "true")
    monkeypatch.setenv("NOTIFICATIONS_DEDUPE_ENABLED", "true")
    monkeypatch.setenv("NOTIFICATIONS_DEDUPE_COOLDOWN_SECONDS", "3600")

    _reload_app_modules()
    app_factory = importlib.import_module("app.app_factory")
    app = app_factory.create_app()

    from app.db import SessionLocal
    from app.models import Host
    from fastapi.testclient import TestClient

    with TestClient(app) as client:
        rr = client.post(
            "/agent/register",
            json={
                "agent_id": "srv-offline-01",
                "hostname": "srv-offline-01",
                "fqdn": None,
                "os_id": "ubuntu",
                "os_version": "24.04",
                "kernel": "test",
                "labels": {"env": "test"},
            },
        )
        assert rr.status_code == 200, rr.text

        # Force host to be offline.
        with SessionLocal() as db:
            h = db.execute(select(Host).where(Host.agent_id == "srv-offline-01")).scalar_one()
            h.last_seen = datetime.now(timezone.utc) - timedelta(days=1)
            db.commit()

        lr = client.post("/auth/login", json={"username": "admin", "password": "admin-password-123"})
        assert lr.status_code == 200, lr.text

        first = client.get("/dashboard/notifications?limit=30")
        assert first.status_code == 200, first.text
        d1 = first.json()
        ids1 = [str(it.get("id") or "") for it in (d1.get("items") or [])]
        assert any(x.startswith("offline:srv-offline-01:") for x in ids1), d1

        second = client.get("/dashboard/notifications?limit=30")
        assert second.status_code == 200, second.text
        d2 = second.json()
        ids2 = [str(it.get("id") or "") for it in (d2.get("items") or [])]
        assert not any(x.startswith("offline:srv-offline-01:") for x in ids2), d2
        assert int(d2.get("suppressed") or 0) >= 1


def test_notifications_dedupe_state_endpoint_admin_only(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "sqlite+pysqlite:///:memory:")
    monkeypatch.setenv("BOOTSTRAP_USERNAME", "admin")
    monkeypatch.setenv("BOOTSTRAP_PASSWORD", "admin-password-123")
    monkeypatch.setenv("MFA_REQUIRE_FOR_PRIVILEGED", "false")
    monkeypatch.setenv("ALLOW_INSECURE_NO_AGENT_TOKEN", "true")
    monkeypatch.setenv("NOTIFICATIONS_DEDUPE_ENABLED", "true")
    monkeypatch.setenv("NOTIFICATIONS_DEDUPE_COOLDOWN_SECONDS", "3600")

    _reload_app_modules()
    app_factory = importlib.import_module("app.app_factory")
    app = app_factory.create_app()

    from app.db import SessionLocal
    from app.models import AppUser, Host
    from fastapi.testclient import TestClient

    with TestClient(app) as admin_client:
        rr = admin_client.post(
            "/agent/register",
            json={
                "agent_id": "srv-offline-02",
                "hostname": "srv-offline-02",
                "fqdn": None,
                "os_id": "ubuntu",
                "os_version": "24.04",
                "kernel": "test",
                "labels": {"env": "test"},
            },
        )
        assert rr.status_code == 200, rr.text

        with SessionLocal() as db:
            h = db.execute(select(Host).where(Host.agent_id == "srv-offline-02")).scalar_one()
            h.last_seen = datetime.now(timezone.utc) - timedelta(days=1)
            db.commit()

        lr = admin_client.post("/auth/login", json={"username": "admin", "password": "admin-password-123"})
        assert lr.status_code == 200, lr.text
        csrf = admin_client.cookies.get("fleet_csrf")
        headers = {"X-CSRF-Token": csrf} if csrf else {}

        # Trigger notifications once so dedupe state is populated.
        n = admin_client.get("/dashboard/notifications?limit=30")
        assert n.status_code == 200, n.text

        # Create readonly user to verify admin-only endpoint protection.
        reg = admin_client.post("/auth/register", json={"username": "viewer", "password": "viewer-pass-123"}, headers=headers)
        assert reg.status_code == 200, reg.text
        with SessionLocal() as db:
            u = db.execute(select(AppUser).where(AppUser.username == "viewer")).scalar_one()
            u.role = "readonly"
            db.commit()

        s = admin_client.get("/dashboard/notifications/dedupe-state?minutes=1440")
        assert s.status_code == 200, s.text
        d = s.json()
        assert int(d.get("count") or 0) >= 1
        assert any((it.get("dedupe_key") or "").startswith("offline:srv-offline-02") for it in (d.get("items") or []))

    with TestClient(app) as viewer_client:
        lr2 = viewer_client.post("/auth/login", json={"username": "viewer", "password": "viewer-pass-123"})
        assert lr2.status_code == 200, lr2.text

        denied = viewer_client.get("/dashboard/notifications/dedupe-state?minutes=1440")
        assert denied.status_code == 403, denied.text
