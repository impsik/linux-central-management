import importlib
import sys
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select


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


def test_two_person_rule_blocks_self_approve_and_audits_creation(monkeypatch):
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

        r = client.post("/jobs/dist-upgrade", json={"agent_ids": ["srv-001"]}, headers=headers)
        assert r.status_code == 200, r.text
        req_id = r.json().get("request_id")
        assert req_id

        r2 = client.post(f"/approvals/admin/{req_id}/approve", headers=headers)
        assert r2.status_code == 403, r2.text
        assert "requester cannot approve" in r2.text.lower()

        a = client.get("/audit?action=high_risk.request.created")
        assert a.status_code == 200, a.text
        items = a.json().get("items") or []
        assert any((it.get("target_type") == "high_risk_action_request" and (it.get("meta") or {}).get("request_id") == req_id) for it in items)


def test_admin_pending_endpoint_supports_recent_mode(monkeypatch):
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

        created = client.post("/jobs/dist-upgrade", json={"agent_ids": ["srv-001"]}, headers=headers)
        assert created.status_code == 200, created.text

        q1 = client.get("/approvals/admin/pending")
        assert q1.status_code == 200, q1.text
        assert q1.json().get("mode") == "pending"

        q2 = client.get("/approvals/admin/pending?mode=recent&hours=24")
        assert q2.status_code == 200, q2.text
        assert q2.json().get("mode") == "recent"
        assert len(q2.json().get("items") or []) >= 1


def test_double_approve_is_idempotent_and_executes_once(monkeypatch):
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

    from app.db import SessionLocal
    from app.models import AppUser, Job
    from fastapi.testclient import TestClient

    with TestClient(app) as requester:
        rr = requester.post(
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

        lr = requester.post("/auth/login", json={"username": "admin", "password": "admin-password-123"})
        assert lr.status_code == 200, lr.text
        csrf = requester.cookies.get("fleet_csrf")
        headers = {"X-CSRF-Token": csrf} if csrf else {}

        reg = requester.post("/auth/register", json={"username": "reviewer", "password": "reviewer-pass-123"}, headers=headers)
        assert reg.status_code == 200, reg.text
        with SessionLocal() as db:
            u = db.execute(select(AppUser).where(AppUser.username == "reviewer")).scalar_one()
            u.role = "admin"
            db.commit()

        created = requester.post("/jobs/dist-upgrade", json={"agent_ids": ["srv-001"]}, headers=headers)
        assert created.status_code == 200, created.text
        req_id = created.json().get("request_id")
        assert req_id

    with TestClient(app) as reviewer:
        lr2 = reviewer.post("/auth/login", json={"username": "reviewer", "password": "reviewer-pass-123"})
        assert lr2.status_code == 200, lr2.text
        csrf2 = reviewer.cookies.get("fleet_csrf")
        headers2 = {"X-CSRF-Token": csrf2} if csrf2 else {}

        first = reviewer.post(f"/approvals/admin/{req_id}/approve", headers=headers2)
        assert first.status_code == 200, first.text
        assert first.json().get("status") == "executed"

        second = reviewer.post(f"/approvals/admin/{req_id}/approve", headers=headers2)
        assert second.status_code == 200, second.text
        assert (second.json().get("summary") or {}).get("already_processed") is True

        with SessionLocal() as db:
            cnt = int(db.execute(select(func.count()).select_from(Job).where(Job.job_type == "dist-upgrade")).scalar_one() or 0)
            assert cnt == 1


def test_approve_then_reject_is_idempotent(monkeypatch):
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

    from app.db import SessionLocal
    from app.models import AppUser
    from fastapi.testclient import TestClient

    with TestClient(app) as requester:
        rr = requester.post(
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

        lr = requester.post("/auth/login", json={"username": "admin", "password": "admin-password-123"})
        assert lr.status_code == 200, lr.text
        csrf = requester.cookies.get("fleet_csrf")
        headers = {"X-CSRF-Token": csrf} if csrf else {}

        reg = requester.post("/auth/register", json={"username": "reviewer", "password": "reviewer-pass-123"}, headers=headers)
        assert reg.status_code == 200, reg.text
        with SessionLocal() as db:
            u = db.execute(select(AppUser).where(AppUser.username == "reviewer")).scalar_one()
            u.role = "admin"
            db.commit()

        created = requester.post("/jobs/dist-upgrade", json={"agent_ids": ["srv-001"]}, headers=headers)
        assert created.status_code == 200, created.text
        req_id = created.json().get("request_id")
        assert req_id

    with TestClient(app) as reviewer:
        lr2 = reviewer.post("/auth/login", json={"username": "reviewer", "password": "reviewer-pass-123"})
        assert lr2.status_code == 200, lr2.text
        csrf2 = reviewer.cookies.get("fleet_csrf")
        headers2 = {"X-CSRF-Token": csrf2} if csrf2 else {}

        first = reviewer.post(f"/approvals/admin/{req_id}/approve", headers=headers2)
        assert first.status_code == 200, first.text
        assert first.json().get("status") == "executed"

        second = reviewer.post(
            f"/approvals/admin/{req_id}/reject",
            headers=headers2,
            json={"note": "late reject should do nothing"},
        )
        assert second.status_code == 200, second.text
        assert second.json().get("status") == "executed"
        assert (second.json().get("summary") or {}).get("already_processed") is True


def test_reject_then_approve_is_idempotent(monkeypatch):
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

    from app.db import SessionLocal
    from app.models import AppUser, Job
    from fastapi.testclient import TestClient

    with TestClient(app) as requester:
        rr = requester.post(
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

        lr = requester.post("/auth/login", json={"username": "admin", "password": "admin-password-123"})
        assert lr.status_code == 200, lr.text
        csrf = requester.cookies.get("fleet_csrf")
        headers = {"X-CSRF-Token": csrf} if csrf else {}

        reg = requester.post("/auth/register", json={"username": "reviewer", "password": "reviewer-pass-123"}, headers=headers)
        assert reg.status_code == 200, reg.text
        with SessionLocal() as db:
            u = db.execute(select(AppUser).where(AppUser.username == "reviewer")).scalar_one()
            u.role = "admin"
            db.commit()

        created = requester.post("/jobs/dist-upgrade", json={"agent_ids": ["srv-001"]}, headers=headers)
        assert created.status_code == 200, created.text
        req_id = created.json().get("request_id")
        assert req_id

    with TestClient(app) as reviewer:
        lr2 = reviewer.post("/auth/login", json={"username": "reviewer", "password": "reviewer-pass-123"})
        assert lr2.status_code == 200, lr2.text
        csrf2 = reviewer.cookies.get("fleet_csrf")
        headers2 = {"X-CSRF-Token": csrf2} if csrf2 else {}

        rej = reviewer.post(f"/approvals/admin/{req_id}/reject", headers=headers2, json={"note": "deny"})
        assert rej.status_code == 200, rej.text
        assert rej.json().get("status") == "rejected"

        appv = reviewer.post(f"/approvals/admin/{req_id}/approve", headers=headers2)
        assert appv.status_code == 200, appv.text
        assert appv.json().get("status") == "rejected"
        assert (appv.json().get("summary") or {}).get("already_processed") is True

        with SessionLocal() as db:
            cnt = int(db.execute(select(func.count()).select_from(Job).where(Job.job_type == "dist-upgrade")).scalar_one() or 0)
            assert cnt == 0


def test_second_admin_can_approve_and_execution_is_audited(monkeypatch):
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

    from app.db import SessionLocal
    from app.models import AppUser
    from fastapi.testclient import TestClient

    with TestClient(app) as requester:
        rr = requester.post(
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

        lr = requester.post("/auth/login", json={"username": "admin", "password": "admin-password-123"})
        assert lr.status_code == 200, lr.text
        csrf = requester.cookies.get("fleet_csrf")
        headers = {"X-CSRF-Token": csrf} if csrf else {}

        reg = requester.post("/auth/register", json={"username": "reviewer", "password": "reviewer-pass-123"}, headers=headers)
        assert reg.status_code == 200, reg.text
        with SessionLocal() as db:
            u = db.execute(select(AppUser).where(AppUser.username == "reviewer")).scalar_one()
            u.role = "admin"
            db.commit()

        created = requester.post("/jobs/dist-upgrade", json={"agent_ids": ["srv-001"]}, headers=headers)
        assert created.status_code == 200, created.text
        req_id = created.json().get("request_id")
        assert req_id

    with TestClient(app) as reviewer:
        lr2 = reviewer.post("/auth/login", json={"username": "reviewer", "password": "reviewer-pass-123"})
        assert lr2.status_code == 200, lr2.text
        csrf2 = reviewer.cookies.get("fleet_csrf")
        headers2 = {"X-CSRF-Token": csrf2} if csrf2 else {}

        approved = reviewer.post(f"/approvals/admin/{req_id}/approve", headers=headers2)
        assert approved.status_code == 200, approved.text
        assert approved.json().get("status") == "executed"
        assert (approved.json().get("summary") or {}).get("target_count") == 1

        a1 = reviewer.get("/audit?action=high_risk.request.approved")
        assert a1.status_code == 200, a1.text
        items1 = a1.json().get("items") or []
        assert any((it.get("meta") or {}).get("request_id") == req_id for it in items1)

        a2 = reviewer.get("/audit?action=high_risk.request.executed")
        assert a2.status_code == 200, a2.text
        items2 = a2.json().get("items") or []
        assert any((it.get("meta") or {}).get("request_id") == req_id for it in items2)
