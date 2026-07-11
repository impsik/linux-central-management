import importlib
import sys


def _reload_app_modules():
    for key in list(sys.modules):
        if key == "app" or key.startswith("app."):
            sys.modules.pop(key, None)


def test_rds_mitigation_catalog_and_assessment_job(monkeypatch):
    for key, value in {
        "DATABASE_URL": "sqlite+pysqlite:///:memory:",
        "BOOTSTRAP_USERNAME": "admin",
        "BOOTSTRAP_PASSWORD": "admin-password-123",
        "UI_COOKIE_SECURE": "false",
        "ALLOW_INSECURE_NO_AGENT_TOKEN": "true",
        "AGENT_SHARED_TOKEN": "",
        "DB_AUTO_CREATE_TABLES": "true",
        "DB_REQUIRE_MIGRATIONS_UP_TO_DATE": "false",
        "MFA_REQUIRE_FOR_PRIVILEGED": "false",
        "CVE_SYNC_ENABLED": "false",
        "METRICS_BACKGROUND_REFRESH_SECONDS": "0",
    }.items():
        monkeypatch.setenv(key, value)

    _reload_app_modules()
    app = importlib.import_module("app.app_factory").create_app()

    from fastapi.testclient import TestClient
    from app.db import SessionLocal
    from app.models import AppUser, AuditEvent
    from sqlalchemy import select

    with TestClient(app) as client:
        registered = client.post("/agent/register", json={
            "agent_id": "srv-mitigation", "hostname": "srv-mitigation",
            "os_id": "ubuntu", "os_version": "24.04", "kernel": "test",
            "labels": {"env": "test"},
        })
        assert registered.status_code == 200, registered.text

        login = client.post("/auth/login", json={"username": "admin", "password": "admin-password-123"})
        assert login.status_code == 200, login.text
        csrf = client.cookies.get("fleet_csrf")
        headers = {"X-CSRF-Token": csrf} if csrf else {}

        catalog = client.get("/security/mitigations")
        assert catalog.status_code == 200, catalog.text
        mitigation = catalog.json()["items"][0]
        assert mitigation["id"] == "linux-rds-disable"
        assert mitigation["version"] == 1
        assert mitigation["apply_available"] is True
        assert mitigation["approval_required"] is True

        unknown = client.post("/security/mitigations/not-real/assess", json={"agent_ids": ["srv-mitigation"]}, headers=headers)
        assert unknown.status_code == 404

        queued = client.post("/security/mitigations/linux-rds-disable/assess", json={"agent_ids": ["srv-mitigation"]}, headers=headers)
        assert queued.status_code == 200, queued.text
        job_id = queued.json()["job_id"]

        claimed = client.get("/agent/next-job", params={"agent_id": "srv-mitigation"})
        assert claimed.status_code == 200, claimed.text
        job = claimed.json()["job"]
        assert job["job_id"] == job_id
        assert job["type"] == "security-mitigation"
        assert job["mitigation_id"] == "linux-rds-disable"
        assert job["mitigation_version"] == 1
        assert job["action"] == "assess"

        completed = client.post("/agent/job-event", json={
            "agent_id": "srv-mitigation", "job_id": job_id, "job_nonce": job["job_nonce"],
            "status": "success", "exit_code": 0,
            "stdout": '{"status":"vulnerable","detail":"rds can be loaded"}',
        })
        assert completed.status_code == 200, completed.text

        apply_request = client.post(
            "/security/mitigations/linux-rds-disable/apply",
            json={"agent_ids": ["srv-mitigation"], "assessment_job_id": job_id},
            headers=headers,
        )
        assert apply_request.status_code == 200, apply_request.text
        assert apply_request.json()["approval_required"] is True
        request_id = apply_request.json()["request_id"]

        pending = client.get("/approvals/admin/pending")
        assert pending.status_code == 200, pending.text
        approval = next(item for item in pending.json()["items"] if item["id"] == request_id)
        assert approval["action"] == "security-mitigation-apply"
        assert approval["payload"]["assessment_job_id"] == job_id

        with SessionLocal() as db:
            from app.routers.auth import pwd_context
            db.add(AppUser(
                username="second-admin", password_hash=pwd_context.hash("second-admin-password-123"),
                role="admin", is_active=True,
            ))
            db.commit()

        with TestClient(app) as approver:
            second_login = approver.post("/auth/login", json={
                "username": "second-admin", "password": "second-admin-password-123",
            })
            assert second_login.status_code == 200, second_login.text
            second_csrf = approver.cookies.get("fleet_csrf")
            second_headers = {"X-CSRF-Token": second_csrf} if second_csrf else {}
            approved = approver.post(f"/approvals/admin/{request_id}/approve", headers=second_headers)
            assert approved.status_code == 200, approved.text
            assert approved.json()["status"] == "executed"
            apply_job_id = approved.json()["execution_ref"]

        apply_claim = client.get("/agent/next-job", params={"agent_id": "srv-mitigation"})
        assert apply_claim.status_code == 200, apply_claim.text
        apply_job = apply_claim.json()["job"]
        assert apply_job["job_id"] == apply_job_id
        assert apply_job["action"] == "apply"

        with SessionLocal() as db:
            audit = db.execute(select(AuditEvent).where(AuditEvent.action == "security.mitigation.assessment.queued")).scalar_one()
            assert audit.target_id == "linux-rds-disable"
            assert audit.meta["mode"] == "ASSESS"
            assert audit.meta["target_count"] == 1
