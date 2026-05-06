import importlib
from datetime import datetime, timezone


def test_cve_high_severity_report_api(monkeypatch):
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
    from app.models import CVEDefinition, CVEPackage, Host, HostPackage, HostPackageUpdate
    from fastapi.testclient import TestClient

    with TestClient(app) as client:
        r = client.post("/auth/login", json={"username": "admin", "password": "admin-password-123"})
        assert r.status_code == 200, r.text

        with SessionLocal() as db:
            host = Host(
                agent_id="srv-cve-1",
                hostname="srv-cve-1",
                os_id="ubuntu",
                os_version="Ubuntu 24.04 noble",
                last_seen=datetime.now(timezone.utc),
                labels={"env": "prod"},
            )
            db.add(host)
            db.flush()
            db.add(
                HostPackage(
                    host_id=host.id,
                    name="openssl",
                    arch="amd64",
                    version="1.0.0",
                    manager="apt",
                    collected_at=datetime.now(timezone.utc),
                )
            )
            db.add(
                HostPackageUpdate(
                    host_id=host.id,
                    name="openssl",
                    installed_version="1.0.0",
                    candidate_version="1.0.3",
                    is_security=True,
                    update_available=True,
                    checked_at=datetime.now(timezone.utc),
                )
            )
            db.add(CVEDefinition(cve_id="CVE-2026-9999", definition_data={"severity": 8.8}, severity="8.8"))
            db.add(
                CVEPackage(
                    cve_id="CVE-2026-9999",
                    package_name="openssl",
                    release="noble",
                    fixed_version="1.0.2",
                    status="released",
                    severity="8.8",
                )
            )
            db.commit()

        r = client.get("/reports/cve-high-severity?min_severity=7.0&sort=severity&order=desc&limit=50")
        assert r.status_code == 200, r.text
        data = r.json()
        assert data["total"] >= 1
        item = next((it for it in data["items"] if it["hostname"] == "srv-cve-1" and it["cve_id"] == "CVE-2026-9999"), None)
        assert item is not None
        assert item["package_name"] == "openssl"
        assert float(item["severity"]) == 8.8
