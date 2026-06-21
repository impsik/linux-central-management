import importlib
import sys


def _reload_app_modules():
    for k in list(sys.modules.keys()):
        if k == "app" or k.startswith("app."):
            sys.modules.pop(k, None)


def _login_admin(client):
    r = client.post("/auth/login", json={"username": "admin", "password": "admin-password-123"})
    assert r.status_code == 200, r.text
    csrf = client.cookies.get("fleet_csrf")
    return {"X-CSRF-Token": csrf} if csrf else {}


def test_agent_version_is_listed_and_disk_cleanup_can_be_queued(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "sqlite+pysqlite:///:memory:")
    monkeypatch.setenv("BOOTSTRAP_USERNAME", "admin")
    monkeypatch.setenv("BOOTSTRAP_PASSWORD", "admin-password-123")
    monkeypatch.setenv("UI_COOKIE_SECURE", "false")
    monkeypatch.setenv("ALLOW_INSECURE_NO_AGENT_TOKEN", "true")
    monkeypatch.setenv("AGENT_SHARED_TOKEN", "")
    monkeypatch.setenv("DB_AUTO_CREATE_TABLES", "true")
    monkeypatch.setenv("DB_REQUIRE_MIGRATIONS_UP_TO_DATE", "false")
    monkeypatch.setenv("MFA_REQUIRE_FOR_PRIVILEGED", "false")

    _reload_app_modules()
    app_factory = importlib.import_module("app.app_factory")
    app = app_factory.create_app()

    from fastapi.testclient import TestClient

    with TestClient(app) as client:
        r = client.post(
            "/agent/register",
            json={
                "agent_id": "srv-health-001",
                "hostname": "srv-health-001",
                "os_id": "ubuntu",
                "os_version": "24.04",
                "kernel": "test",
                "agent_version": "0.0.3-alpha",
                "labels": {"env": "test", "role": "worker"},
            },
        )
        assert r.status_code == 200, r.text

        headers = _login_admin(client)

        r = client.get("/hosts")
        assert r.status_code == 200, r.text
        hosts = r.json()
        row = next(h for h in hosts if h["agent_id"] == "srv-health-001")
        assert row["agent_version"] == "0.0.3-alpha"
        assert row["is_online"] is True
        assert isinstance(row["last_seen_seconds_ago"], (int, float))

        r = client.get("/reports/hosts-updates?only_pending=false&online_only=false")
        assert r.status_code == 200, r.text
        report_items = r.json()["items"]
        report_row = next(h for h in report_items if h["agent_id"] == "srv-health-001")
        assert report_row["agent_version"] == "0.0.3-alpha"

        r = client.post(
            "/hosts/srv-health-001/disk-cleanup?wait=false",
            json={"dry_run": True, "actions": ["apt_cache", "journald"]},
            headers=headers,
        )
        assert r.status_code == 200, r.text
        data = r.json()
        assert data["status"] == "queued"
        assert data["dry_run"] is True
        assert data["actions"] == ["apt_cache", "journald"]
        assert data["job_id"]
