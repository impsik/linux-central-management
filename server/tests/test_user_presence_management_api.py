import importlib
from datetime import datetime, timedelta, timezone

from sqlalchemy import select


def _boot_app(monkeypatch):
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
    monkeypatch.setattr("app.services.cve_sync.cve_sync_loop", lambda stop_event: stop_event.wait())
    return app_factory.create_app()


def test_user_presence_search_and_fleet_lock_targets_online_matches(monkeypatch):
    app = _boot_app(monkeypatch)

    from app.db import SessionLocal
    from app.models import Host, HostUser, Job, JobRun
    from app.routers import reports
    from fastapi.testclient import TestClient

    with TestClient(app) as client:
        monkeypatch.setattr(reports, "is_host_online", lambda host, now=None: host.agent_id != "srv-offline")

        for aid in ("srv-online", "srv-offline", "srv-other"):
            r = client.post(
                "/agent/register",
                json={
                    "agent_id": aid,
                    "hostname": aid,
                    "fqdn": None,
                    "os_id": "ubuntu",
                    "os_version": "24.04",
                    "kernel": "test",
                    "labels": {"env": "test"},
                },
            )
            assert r.status_code == 200, r.text

        with SessionLocal() as db:
            hosts = {h.agent_id: h for h in db.execute(select(Host)).scalars().all()}
            hosts["srv-online"].last_seen = datetime.now(timezone.utc)
            hosts["srv-other"].last_seen = datetime.now(timezone.utc)
            hosts["srv-offline"].last_seen = datetime.now(timezone.utc) - timedelta(hours=2)
            for aid in ("srv-online", "srv-offline"):
                db.add(
                    HostUser(
                        host_id=hosts[aid].id,
                        username="mihkel",
                        uid=1001,
                        gid=1001,
                        home="/home/mihkel",
                        shell="/bin/bash",
                        has_sudo=False,
                        is_locked=False,
                    )
                )
            db.add(
                HostUser(
                    host_id=hosts["srv-other"].id,
                    username="mari",
                    uid=1002,
                    gid=1002,
                    home="/home/mari",
                    shell="/bin/bash",
                    has_sudo=True,
                    is_locked=False,
                )
            )
            db.commit()

        r = client.post("/auth/login", json={"username": "admin", "password": "admin-password-123"})
        assert r.status_code == 200, r.text
        csrf = client.cookies.get("fleet_csrf")
        headers = {"X-CSRF-Token": csrf} if csrf else {}

        search = client.get("/reports/user-presence", params={"username": "mihkel", "exact": True})
        assert search.status_code == 200, search.text
        data = search.json()
        assert data["total"] == 2
        assert {item["agent_id"] for item in data["items"]} == {"srv-online", "srv-offline"}

        lock = client.post(
            "/reports/user-presence/lock",
            json={"username": "mihkel", "agent_ids": ["srv-online", "srv-offline"]},
            headers=headers,
        )
        assert lock.status_code == 200, lock.text
        out = lock.json()
        assert out["targets"] == ["srv-online"]
        assert out["skipped_offline"] == ["srv-offline"]

        with SessionLocal() as db:
            job = db.execute(select(Job).where(Job.job_key == out["job_id"])).scalar_one()
            assert job.job_type == "user-lock"
            runs = db.execute(select(JobRun).where(JobRun.job_id == job.id)).scalars().all()
            assert [run.agent_id for run in runs] == ["srv-online"]


def test_service_presence_action_targets_online_selected_hosts(monkeypatch):
    app = _boot_app(monkeypatch)

    from app.db import SessionLocal
    from app.models import Host, Job, JobRun
    from app.routers import reports
    from fastapi.testclient import TestClient

    with TestClient(app) as client:
        monkeypatch.setattr(reports, "is_host_online", lambda host, now=None: host.agent_id != "srv-offline")

        for aid in ("srv-online", "srv-offline"):
            r = client.post(
                "/agent/register",
                json={
                    "agent_id": aid,
                    "hostname": aid,
                    "fqdn": None,
                    "os_id": "ubuntu",
                    "os_version": "24.04",
                    "kernel": "test",
                    "labels": {"env": "test"},
                },
            )
            assert r.status_code == 200, r.text

        with SessionLocal() as db:
            hosts = {h.agent_id: h for h in db.execute(select(Host)).scalars().all()}
            hosts["srv-online"].last_seen = datetime.now(timezone.utc)
            hosts["srv-offline"].last_seen = datetime.now(timezone.utc) - timedelta(hours=2)
            db.commit()

        r = client.post("/auth/login", json={"username": "admin", "password": "admin-password-123"})
        assert r.status_code == 200, r.text
        csrf = client.cookies.get("fleet_csrf")
        headers = {"X-CSRF-Token": csrf} if csrf else {}

        stop = client.post(
            "/reports/service-presence/stop",
            json={"service_name": "nginx", "agent_ids": ["srv-online", "srv-offline"]},
            headers=headers,
        )
        assert stop.status_code == 200, stop.text
        out = stop.json()
        assert out["targets"] == ["srv-online"]
        assert out["skipped_offline"] == ["srv-offline"]

        with SessionLocal() as db:
            job = db.execute(select(Job).where(Job.job_key == out["job_id"])).scalar_one()
            assert job.job_type == "service-control"
            assert job.payload["service_name"] == "nginx"
            assert job.payload["action"] == "stop"
            runs = db.execute(select(JobRun).where(JobRun.job_id == job.id)).scalars().all()
            assert [run.agent_id for run in runs] == ["srv-online"]

        enable = client.post(
            "/reports/service-presence/enable",
            json={"service_name": "nginx", "agent_ids": ["srv-online", "srv-offline"]},
            headers=headers,
        )
        assert enable.status_code == 200, enable.text
        out = enable.json()
        assert out["targets"] == ["srv-online"]
        assert out["skipped_offline"] == ["srv-offline"]

        with SessionLocal() as db:
            job = db.execute(select(Job).where(Job.job_key == out["job_id"])).scalar_one()
            assert job.job_type == "service-control"
            assert job.payload["service_name"] == "nginx"
            assert job.payload["action"] == "enable"
            runs = db.execute(select(JobRun).where(JobRun.job_id == job.id)).scalars().all()
            assert [run.agent_id for run in runs] == ["srv-online"]

        start = client.post(
            "/reports/service-presence/start",
            json={"service_name": "nginx", "agent_ids": ["srv-online", "srv-offline"]},
            headers=headers,
        )
        assert start.status_code == 200, start.text
        out = start.json()
        assert out["targets"] == ["srv-online"]
        assert out["skipped_offline"] == ["srv-offline"]

        with SessionLocal() as db:
            job = db.execute(select(Job).where(Job.job_key == out["job_id"])).scalar_one()
            assert job.job_type == "service-control"
            assert job.payload["service_name"] == "nginx"
            assert job.payload["action"] == "start"
            runs = db.execute(select(JobRun).where(JobRun.job_id == job.id)).scalars().all()
            assert [run.agent_id for run in runs] == ["srv-online"]
