import importlib


def test_dashboard_slo_api_smoke(monkeypatch):
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

    from fastapi.testclient import TestClient

    with TestClient(app) as client:
        # create host for offline ratio metric
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

        # login to access dashboard API
        r = client.post("/auth/login", json={"username": "admin", "password": "admin-password-123"})
        assert r.status_code == 200, r.text

        slo = client.get("/dashboard/slo", params={"hours": 24})
        assert slo.status_code == 200, slo.text
        data = slo.json()

        assert data["window_hours"] == 24
        assert "kpis" in data
        assert "job_success_rate" in data["kpis"]
        assert "median_patch_duration" in data["kpis"]
        assert "auth_error_rate" in data["kpis"]
        assert "offline_host_ratio" in data["kpis"]
