import importlib


def test_jobs_preflight_and_dry_run_no_job_creation(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "sqlite+pysqlite:///:memory:")
    monkeypatch.setenv("BOOTSTRAP_USERNAME", "admin")
    monkeypatch.setenv("BOOTSTRAP_PASSWORD", "admin-password-123")
    monkeypatch.setenv("UI_COOKIE_SECURE", "false")
    monkeypatch.setenv("ALLOW_INSECURE_NO_AGENT_TOKEN", "true")
    monkeypatch.setenv("AGENT_SHARED_TOKEN", "")
    monkeypatch.setenv("DB_AUTO_CREATE_TABLES", "true")
    monkeypatch.setenv("DB_REQUIRE_MIGRATIONS_UP_TO_DATE", "false")
    monkeypatch.setenv("MFA_REQUIRE_FOR_PRIVILEGED", "false")
    monkeypatch.setenv("AGENT_ONLINE_GRACE_SECONDS", "3600")

    app_factory = importlib.import_module("app.app_factory")
    app = app_factory.create_app()

    from fastapi.testclient import TestClient

    with TestClient(app) as client:
        r = client.post(
            "/agent/register",
            json={
                "agent_id": "srv-online",
                "hostname": "srv-online",
                "os_id": "ubuntu",
                "os_version": "22.04",
                "kernel": "test",
                "labels": {"env": "test"},
            },
        )
        assert r.status_code == 200, r.text

        r = client.post("/auth/login", json={"username": "admin", "password": "admin-password-123"})
        assert r.status_code == 200, r.text
        csrf = client.cookies.get("fleet_csrf")
        headers = {"X-CSRF-Token": csrf} if csrf else {}

        p = client.post("/jobs/preflight", json={"agent_ids": ["srv-online", "srv-unknown"]}, headers=headers)
        assert p.status_code == 200, p.text
        pre = p.json()
        assert "srv-online" in pre["targeted_hosts"]
        assert "srv-unknown" in pre["offline_or_unreachable"]

        before = client.get("/jobs", params={"type": "dist-upgrade", "limit": 200}, headers=headers)
        assert before.status_code == 200, before.text
        before_count = int(before.json().get("total", 0))

        r = client.post("/jobs/dist-upgrade", json={"agent_ids": ["srv-online"], "dry_run": True}, headers=headers)
        assert r.status_code == 200, r.text
        data = r.json()
        assert data["dry_run"] is True
        assert data["type"] == "dist-upgrade"
        assert data["predicted_actions"][0]["agent_id"] == "srv-online"

        after = client.get("/jobs", params={"type": "dist-upgrade", "limit": 200}, headers=headers)
        assert after.status_code == 200, after.text
        after_count = int(after.json().get("total", 0))
        assert after_count == before_count


def test_pkg_upgrade_dry_run_returns_predicted_packages(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "sqlite+pysqlite:///:memory:")
    monkeypatch.setenv("BOOTSTRAP_USERNAME", "admin")
    monkeypatch.setenv("BOOTSTRAP_PASSWORD", "admin-password-123")
    monkeypatch.setenv("UI_COOKIE_SECURE", "false")
    monkeypatch.setenv("ALLOW_INSECURE_NO_AGENT_TOKEN", "true")
    monkeypatch.setenv("AGENT_SHARED_TOKEN", "")
    monkeypatch.setenv("DB_AUTO_CREATE_TABLES", "true")
    monkeypatch.setenv("DB_REQUIRE_MIGRATIONS_UP_TO_DATE", "false")
    monkeypatch.setenv("MFA_REQUIRE_FOR_PRIVILEGED", "false")
    monkeypatch.setenv("AGENT_ONLINE_GRACE_SECONDS", "3600")

    app_factory = importlib.import_module("app.app_factory")
    app = app_factory.create_app()

    from fastapi.testclient import TestClient

    with TestClient(app) as client:
        r = client.post(
            "/agent/register",
            json={
                "agent_id": "srv-001",
                "hostname": "srv-001",
                "os_id": "ubuntu",
                "os_version": "22.04",
                "kernel": "test",
                "labels": {"env": "test"},
            },
        )
        assert r.status_code == 200, r.text

        r = client.post("/auth/login", json={"username": "admin", "password": "admin-password-123"})
        assert r.status_code == 200, r.text
        csrf = client.cookies.get("fleet_csrf")
        headers = {"X-CSRF-Token": csrf} if csrf else {}

        before = client.get("/jobs", params={"type": "pkg-upgrade", "limit": 200}, headers=headers)
        assert before.status_code == 200, before.text
        before_count = int(before.json().get("total", 0))

        r = client.post(
            "/jobs/pkg-upgrade",
            json={"agent_ids": ["srv-001"], "packages": ["bash"], "dry_run": True},
            headers=headers,
        )
        assert r.status_code == 200, r.text
        data = r.json()
        assert data["dry_run"] is True
        assert data["predicted_actions"][0]["packages"] == ["bash"]

        after = client.get("/jobs", params={"type": "pkg-upgrade", "limit": 200}, headers=headers)
        assert after.status_code == 200, after.text
        after_count = int(after.json().get("total", 0))
        assert after_count == before_count
