import os
import importlib
from datetime import datetime, timedelta, timezone
from fastapi import HTTPException
from sqlalchemy import select


def _job_nonce(job_id: str, agent_id: str) -> str:
    from app.db import SessionLocal
    from app.models import Job, JobRun

    with SessionLocal() as db:
        row = (
            db.execute(
                select(JobRun)
                .join(Job, Job.id == JobRun.job_id)
                .where(Job.job_key == job_id, JobRun.agent_id == agent_id)
            )
            .scalar_one()
        )
        return row.job_nonce


def test_job_flow_sqlite(monkeypatch):
    # Configure test environment BEFORE importing app modules (engine is created at import time).
    monkeypatch.setenv("DATABASE_URL", "sqlite+pysqlite:///:memory:")
    monkeypatch.setenv("BOOTSTRAP_USERNAME", "admin")
    monkeypatch.setenv("BOOTSTRAP_PASSWORD", "admin-password-123")
    monkeypatch.setenv("UI_COOKIE_SECURE", "false")
    monkeypatch.setenv("ALLOW_INSECURE_NO_AGENT_TOKEN", "true")
    monkeypatch.setenv("AGENT_SHARED_TOKEN", "")
    monkeypatch.setenv("DB_AUTO_CREATE_TABLES", "true")
    monkeypatch.setenv("DB_REQUIRE_MIGRATIONS_UP_TO_DATE", "false")
    monkeypatch.setenv("MFA_REQUIRE_FOR_PRIVILEGED", "false")
    monkeypatch.setenv("CVE_SYNC_ENABLED", "false")
    monkeypatch.setenv("METRICS_BACKGROUND_REFRESH_SECONDS", "0")

    # Import after env is set
    app_factory = importlib.import_module("app.app_factory")

    app = app_factory.create_app()

    from fastapi.testclient import TestClient
    from app.db import SessionLocal
    from app.models import AuditEvent

    with TestClient(app) as client:
        # Monkeypatch ansible runner to avoid calling external ansible-playbook
        def fake_run_playbook(playbook, agent_ids, extra_vars, *args, **kwargs):
            return {"ok": True, "rc": 0, "stdout": "ok", "stderr": "", "log_name": "test.log", "log_path": None}
        # Patch both the service function and the router-imported symbol.
        ansible_mod = importlib.import_module("app.services.ansible")
        monkeypatch.setattr(ansible_mod, "run_playbook", fake_run_playbook)
        ansible_router = importlib.import_module("app.routers.ansible")
        monkeypatch.setattr(ansible_router, "run_playbook", fake_run_playbook)
        # Agent registers (no UI auth required)
        r = client.post(
            "/agent/register",
            json={
                "agent_id": "srv-001",
                "hostname": "srv-001",
                "fqdn": None,
                "os_id": "ubuntu",
                "os_version": "22.04",
                "kernel": "test",
                "labels": {"env": "test"},
            },
        )
        assert r.status_code == 200, r.text

        # Login (bootstrap seeded on startup)
        r = client.post("/auth/login", json={"username": "admin", "password": "admin-password-123"})
        assert r.status_code == 200, r.text

        csrf = client.cookies.get("fleet_csrf")
        headers = {"X-CSRF-Token": csrf} if csrf else {}

        # Create a query job
        r = client.post("/jobs/pkg-query", json={"agent_ids": ["srv-001"], "packages": ["bash"]}, headers=headers)
        assert r.status_code == 200, r.text
        job_id = r.json()["job_id"]
        job_nonce = _job_nonce(job_id, "srv-001")

        bad_nonce = client.post(
            "/agent/job-event",
            json={"agent_id": "srv-001", "job_id": job_id, "status": "running"},
        )
        assert bad_nonce.status_code == 403, bad_nonce.text
        with SessionLocal() as db:
            invalid_nonce_event = db.execute(
                select(AuditEvent).where(AuditEvent.action == "agent.job_event.invalid_nonce")
            ).scalar_one()
            assert invalid_nonce_event.meta["agent_id"] == "srv-001"

        # Agent reports job running + success
        r = client.post(
            "/agent/job-event",
            json={"agent_id": "srv-001", "job_id": job_id, "job_nonce": job_nonce, "status": "running"},
        )
        assert r.status_code == 200, r.text

        r = client.post(
            "/agent/job-event",
            json={
                "agent_id": "srv-001",
                "job_id": job_id,
                "job_nonce": job_nonce,
                "status": "success",
                "exit_code": 0,
                "stdout": '{"packages":[{"name":"bash","version":"5.1","found":true}]}',
                "stderr": "pkg-query warning tail",
            },
        )
        assert r.status_code == 200, r.text

        # Server job status should reflect completion
        r = client.get(f"/jobs/{job_id}")
        assert r.status_code == 200, r.text
        data = r.json()
        assert data["done"] is True
        assert data["type"] == "query-pkg-version"
        assert data["result"] is not None
        assert "packages" in data["result"]
        run = data["runs"][0]
        assert run["stdout_tail"] == '{"packages":[{"name":"bash","version":"5.1","found":true}]}'
        assert run["stdout_tail_truncated"] is False
        assert run["stderr_tail"] == "pkg-query warning tail"
        assert run["stderr_tail_truncated"] is False

        # Jobs list endpoint (API v2 style)
        r = client.get("/jobs", params={"agent_id": "srv-001", "limit": 10, "offset": 0})
        assert r.status_code == 200, r.text
        lst = r.json()
        assert "items" in lst and isinstance(lst["items"], list)
        assert lst["total"] >= 1
        assert any(it["job_id"] == job_id for it in lst["items"])

        # Ansible run persistence (API v2 style)
        # Ensure the log artifact exists for /ansible/runs/{id}/log
        from app.services.ansible import ANSIBLE_LOG_DIR
        ansible_logs_dir = ANSIBLE_LOG_DIR
        ansible_logs_dir.mkdir(parents=True, exist_ok=True)
        (ansible_logs_dir / "test.log").write_text("hello log", encoding="utf-8")

        r = client.post("/ansible/run", json={"playbook": "noop.yml", "agent_ids": ["srv-001"], "extra_vars": {"secret": "x"}}, headers=headers)
        assert r.status_code == 200, r.text
        run_id = r.json()["run_id"]

        r = client.get("/ansible/runs", params={"limit": 10, "offset": 0})
        assert r.status_code == 200, r.text
        runs = r.json()
        assert runs["total"] >= 1
        assert any(it["run_id"] == run_id for it in runs["items"])

        r = client.get(f"/ansible/runs/{run_id}")
        assert r.status_code == 200, r.text
        detail = r.json()
        assert detail["run_id"] == run_id
        # extra_vars stored redacted-only; in this case playbook prompts unknown so redact_extra_vars returns {}
        assert "extra_vars" in detail

        r = client.get(f"/ansible/runs/{run_id}/log")
        assert r.status_code == 200, r.text
        assert "hello log" in r.text

        # HTTPException path should keep actionable error detail in persisted run record.
        def fake_run_playbook_httperr(playbook, agent_ids, extra_vars, *args, **kwargs):
            raise HTTPException(status_code=404, detail="Playbook not found")

        monkeypatch.setattr(ansible_mod, "run_playbook", fake_run_playbook_httperr)
        monkeypatch.setattr(ansible_router, "run_playbook", fake_run_playbook_httperr)

        r = client.post("/ansible/run", json={"playbook": "missing.yml", "agent_ids": ["srv-001"]}, headers=headers)
        assert r.status_code == 404, r.text
        fail_runs = client.get("/ansible/runs", params={"status": "failed", "limit": 10, "offset": 0})
        assert fail_runs.status_code == 200, fail_runs.text
        failed_item = next((it for it in fail_runs.json().get("items", []) if it.get("playbook") == "missing.yml"), None)
        assert failed_item is not None

        fr = client.get(f"/ansible/runs/{failed_item['run_id']}")
        assert fr.status_code == 200, fr.text
        assert fr.json().get("stderr") == "Playbook not found"


def test_jobs_readonly_cannot_run_and_cannot_read_out_of_scope(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "sqlite+pysqlite:///:memory:")
    monkeypatch.setenv("BOOTSTRAP_USERNAME", "admin")
    monkeypatch.setenv("BOOTSTRAP_PASSWORD", "admin-password-123")
    monkeypatch.setenv("UI_COOKIE_SECURE", "false")
    monkeypatch.setenv("ALLOW_INSECURE_NO_AGENT_TOKEN", "true")
    monkeypatch.setenv("AGENT_SHARED_TOKEN", "")
    monkeypatch.setenv("DB_AUTO_CREATE_TABLES", "true")
    monkeypatch.setenv("DB_REQUIRE_MIGRATIONS_UP_TO_DATE", "false")
    monkeypatch.setenv("MFA_REQUIRE_FOR_PRIVILEGED", "false")
    monkeypatch.setenv("CVE_SYNC_ENABLED", "false")
    monkeypatch.setenv("METRICS_BACKGROUND_REFRESH_SECONDS", "0")

    app_factory = importlib.import_module("app.app_factory")
    app = app_factory.create_app()

    from app.db import SessionLocal
    from app.models import AppUser, AppUserScope
    from fastapi.testclient import TestClient

    with TestClient(app) as admin_client:
        for aid, env in (("srv-prod", "prod"), ("srv-dev", "dev")):
            rr = admin_client.post(
                "/agent/register",
                json={
                    "agent_id": aid,
                    "hostname": aid,
                    "fqdn": None,
                    "os_id": "ubuntu",
                    "os_version": "24.04",
                    "kernel": "test",
                    "labels": {"env": env},
                },
            )
            assert rr.status_code == 200, rr.text

        lr = admin_client.post("/auth/login", json={"username": "admin", "password": "admin-password-123"})
        assert lr.status_code == 200, lr.text
        csrf = admin_client.cookies.get("fleet_csrf")
        headers = {"X-CSRF-Token": csrf} if csrf else {}

        reg = admin_client.post("/auth/register", json={"username": "viewer", "password": "viewer-pass-123"}, headers=headers)
        assert reg.status_code == 200, reg.text

        with SessionLocal() as db:
            viewer = db.execute(select(AppUser).where(AppUser.username == "viewer")).scalar_one()
            viewer.role = "readonly"
            db.add(AppUserScope(user_id=viewer.id, scope_type="label_selector", selector={"env": ["prod"]}))
            db.commit()

        # Create a job against dev host and store host output.
        create = admin_client.post(
            "/jobs/pkg-query",
            json={"agent_ids": ["srv-dev"], "packages": ["bash"]},
            headers=headers,
        )
        assert create.status_code == 200, create.text
        job_id = create.json()["job_id"]
        job_nonce = _job_nonce(job_id, "srv-dev")

        ev = admin_client.post(
            "/agent/job-event",
            json={
                "agent_id": "srv-dev",
                "job_id": job_id,
                "job_nonce": job_nonce,
                "status": "success",
                "exit_code": 0,
                "stdout": '{"packages":[{"name":"bash","version":"5.1","found":true}]}',
            },
        )
        assert ev.status_code == 200, ev.text

    with TestClient(app) as viewer_client:
        lr2 = viewer_client.post("/auth/login", json={"username": "viewer", "password": "viewer-pass-123"})
        assert lr2.status_code == 200, lr2.text
        viewer_csrf = viewer_client.cookies.get("fleet_csrf")
        viewer_headers = {"X-CSRF-Token": viewer_csrf} if viewer_csrf else {}

        denied_write = viewer_client.post(
            "/jobs/pkg-query",
            json={"agent_ids": ["srv-prod"], "packages": ["bash"]},
            headers=viewer_headers,
        )
        assert denied_write.status_code == 403, denied_write.text

        hidden_job = viewer_client.get(f"/jobs/{job_id}")
        assert hidden_job.status_code == 404, hidden_job.text

        hidden_stdout = viewer_client.get(f"/jobs/{job_id}/runs/srv-dev/stdout.txt")
        assert hidden_stdout.status_code == 404, hidden_stdout.text


def test_ansible_requires_operator_and_owned_targets(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "sqlite+pysqlite:///:memory:")
    monkeypatch.setenv("BOOTSTRAP_USERNAME", "admin")
    monkeypatch.setenv("BOOTSTRAP_PASSWORD", "admin-password-123")
    monkeypatch.setenv("UI_COOKIE_SECURE", "false")
    monkeypatch.setenv("ALLOW_INSECURE_NO_AGENT_TOKEN", "true")
    monkeypatch.setenv("AGENT_SHARED_TOKEN", "")
    monkeypatch.setenv("DB_AUTO_CREATE_TABLES", "true")
    monkeypatch.setenv("DB_REQUIRE_MIGRATIONS_UP_TO_DATE", "false")
    monkeypatch.setenv("MFA_REQUIRE_FOR_PRIVILEGED", "false")
    monkeypatch.setenv("CVE_SYNC_ENABLED", "false")
    monkeypatch.setenv("METRICS_BACKGROUND_REFRESH_SECONDS", "0")

    app_factory = importlib.import_module("app.app_factory")
    app = app_factory.create_app()

    def fake_run_playbook(playbook, agent_ids, extra_vars, *args, **kwargs):
        return {"ok": True, "rc": 0, "stdout": "ok", "stderr": "", "log_name": None, "log_path": None}

    ansible_mod = importlib.import_module("app.services.ansible")
    monkeypatch.setattr(ansible_mod, "run_playbook", fake_run_playbook)
    ansible_router = importlib.import_module("app.routers.ansible")
    monkeypatch.setattr(ansible_router, "run_playbook", fake_run_playbook)

    from app.db import SessionLocal
    from app.models import AppUser
    from fastapi.testclient import TestClient

    with TestClient(app) as admin_client:
        for aid, owner in (("srv-owned", "ansible-op"), ("srv-other", "alice")):
            rr = admin_client.post(
                "/agent/register",
                json={
                    "agent_id": aid,
                    "hostname": aid,
                    "fqdn": None,
                    "os_id": "ubuntu",
                    "os_version": "24.04",
                    "kernel": "test",
                    "labels": {"owner": owner},
                },
            )
            assert rr.status_code == 200, rr.text

        with SessionLocal() as db:
            from app.routers.auth import pwd_context
            from app.services.ansible_runs import create_run

            op = AppUser(
                username="ansible-op",
                password_hash=pwd_context.hash("user-pass-123"),
                role="operator",
                is_active=True,
            )
            viewer = AppUser(
                username="ansible-viewer",
                password_hash=pwd_context.hash("user-pass-123"),
                role="readonly",
                is_active=True,
            )
            db.add(op)
            db.add(viewer)
            hidden_run = create_run(
                db=db,
                playbook="noop.yml",
                targets=["srv-other"],
                extra_vars_redacted={},
                created_by="admin",
            )
            hidden_run.status = "success"
            db.commit()
            hidden_run_id = hidden_run.run_key

    with TestClient(app) as op_client:
        lr2 = op_client.post("/auth/login", json={"username": "ansible-op", "password": "user-pass-123"})
        assert lr2.status_code == 200, lr2.text
        op_csrf = op_client.cookies.get("fleet_csrf")
        op_headers = {"X-CSRF-Token": op_csrf} if op_csrf else {}

        allowed = op_client.post(
            "/ansible/run",
            json={"playbook": "noop.yml", "agent_ids": ["srv-owned"]},
            headers=op_headers,
        )
        assert allowed.status_code == 200, allowed.text

        denied_target = op_client.post(
            "/ansible/run",
            json={"playbook": "noop.yml", "agent_ids": ["srv-other"]},
            headers=op_headers,
        )
        assert denied_target.status_code == 404, denied_target.text

        hidden_detail = op_client.get(f"/ansible/runs/{hidden_run_id}")
        assert hidden_detail.status_code == 404, hidden_detail.text

    with TestClient(app) as viewer_client:
        lr3 = viewer_client.post("/auth/login", json={"username": "ansible-viewer", "password": "user-pass-123"})
        assert lr3.status_code == 200, lr3.text
        viewer_csrf = viewer_client.cookies.get("fleet_csrf")
        viewer_headers = {"X-CSRF-Token": viewer_csrf} if viewer_csrf else {}

        denied_readonly = viewer_client.post(
            "/ansible/run",
            json={"playbook": "noop.yml", "agent_ids": ["srv-owned"]},
            headers=viewer_headers,
        )
        assert denied_readonly.status_code == 403, denied_readonly.text


def test_pkg_upgrade_success_invalidates_cve_cache_and_queues_inventory(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "sqlite+pysqlite:///:memory:")
    monkeypatch.setenv("BOOTSTRAP_USERNAME", "admin")
    monkeypatch.setenv("BOOTSTRAP_PASSWORD", "admin-password-123")
    monkeypatch.setenv("UI_COOKIE_SECURE", "false")
    monkeypatch.setenv("ALLOW_INSECURE_NO_AGENT_TOKEN", "true")
    monkeypatch.setenv("AGENT_SHARED_TOKEN", "")
    monkeypatch.setenv("DB_AUTO_CREATE_TABLES", "true")
    monkeypatch.setenv("DB_REQUIRE_MIGRATIONS_UP_TO_DATE", "false")
    monkeypatch.setenv("MFA_REQUIRE_FOR_PRIVILEGED", "false")
    monkeypatch.setenv("CVE_SYNC_ENABLED", "false")
    monkeypatch.setenv("METRICS_BACKGROUND_REFRESH_SECONDS", "0")

    app_factory = importlib.import_module("app.app_factory")
    app = app_factory.create_app()

    from app.db import SessionLocal
    from app.models import Host, HostCVEStatus, Job, JobRun
    from app.services.jobs import create_job_with_runs
    from fastapi.testclient import TestClient

    with TestClient(app) as client:
        r = client.post(
            "/agent/register",
            json={
                "agent_id": "srv-cve",
                "hostname": "srv-cve",
                "fqdn": None,
                "os_id": "ubuntu",
                "os_version": "24.04",
                "kernel": "test",
                "labels": {"env": "test"},
            },
        )
        assert r.status_code == 200, r.text

        with SessionLocal() as db:
            host = db.execute(select(Host).where(Host.agent_id == "srv-cve")).scalar_one()
            db.add(
                HostCVEStatus(
                    host_id=host.id,
                    cve="CVE-2026-24061",
                    affected=True,
                    checked_at=datetime.now(timezone.utc),
                    raw="stale vulnerable result",
                )
            )
            created = create_job_with_runs(
                db=db,
                job_type="pkg-upgrade",
                payload={"packages": ["openssl"], "packages_by_agent": {}, "dry_run": False},
                agent_ids=["srv-cve"],
                commit=False,
            )
            db.commit()

        job_id = created.job_key
        job_nonce = _job_nonce(job_id, "srv-cve")

        done = client.post(
            "/agent/job-event",
            json={
                "agent_id": "srv-cve",
                "job_id": job_id,
                "job_nonce": job_nonce,
                "status": "success",
                "exit_code": 0,
                "stdout": "upgrade completed",
            },
        )
        assert done.status_code == 200, done.text

        with SessionLocal() as db:
            host = db.execute(select(Host).where(Host.agent_id == "srv-cve")).scalar_one()
            stale = db.execute(
                select(HostCVEStatus).where(
                    HostCVEStatus.host_id == host.id,
                    HostCVEStatus.cve == "CVE-2026-24061",
                )
            ).scalar_one_or_none()
            assert stale is None

            refresh = (
                db.execute(
                    select(JobRun, Job)
                    .join(Job, Job.id == JobRun.job_id)
                    .where(
                        Job.job_type == "inventory-now",
                        JobRun.agent_id == "srv-cve",
                        JobRun.status == "queued",
                    )
                )
                .first()
            )
            assert refresh is not None
            assert refresh[1].payload["reason"] == "post-pkg-upgrade"


def test_agent_next_job_claims_durable_db_queue_without_dispatcher(monkeypatch):
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
    from app.models import Job, JobRun
    from app.services.jobs import create_job_with_runs
    from fastapi.testclient import TestClient

    with TestClient(app) as client:
        r = client.post(
            "/agent/register",
            json={
                "agent_id": "srv-durable",
                "hostname": "srv-durable",
                "fqdn": None,
                "os_id": "ubuntu",
                "os_version": "24.04",
                "kernel": "test",
                "labels": {"env": "test"},
            },
        )
        assert r.status_code == 200, r.text

        with SessionLocal() as db:
            created = create_job_with_runs(
                db=db,
                job_type="pkg-upgrade",
                payload={
                    "packages": ["bash"],
                    "packages_by_agent": {"srv-durable": ["openssl"]},
                    "dry_run": False,
                },
                agent_ids=["srv-durable"],
                commit=False,
            )
            db.commit()
            job_id = created.job_key

        r = client.get("/agent/next-job", params={"agent_id": "srv-durable"})
        assert r.status_code == 200, r.text
        job = r.json()["job"]
        assert job["job_id"] == job_id
        assert job["type"] == "pkg-upgrade"
        assert job["packages"] == ["openssl"]
        assert job["job_nonce"]

        with SessionLocal() as db:
            run = (
                db.execute(
                    select(JobRun)
                    .join(Job, Job.id == JobRun.job_id)
                    .where(Job.job_key == job_id, JobRun.agent_id == "srv-durable")
                )
                .scalar_one()
            )
            assert run.status == "running"
            assert run.started_at is not None
            assert run.job_nonce == job["job_nonce"]


def test_agent_next_job_recovers_stale_running_job_once_then_fails(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "sqlite+pysqlite:///:memory:")
    monkeypatch.setenv("BOOTSTRAP_USERNAME", "admin")
    monkeypatch.setenv("BOOTSTRAP_PASSWORD", "admin-password-123")
    monkeypatch.setenv("UI_COOKIE_SECURE", "false")
    monkeypatch.setenv("ALLOW_INSECURE_NO_AGENT_TOKEN", "true")
    monkeypatch.setenv("AGENT_SHARED_TOKEN", "")
    monkeypatch.setenv("DB_AUTO_CREATE_TABLES", "true")
    monkeypatch.setenv("DB_REQUIRE_MIGRATIONS_UP_TO_DATE", "false")
    monkeypatch.setenv("MFA_REQUIRE_FOR_PRIVILEGED", "false")
    monkeypatch.setenv("CVE_SYNC_ENABLED", "false")
    monkeypatch.setenv("METRICS_BACKGROUND_REFRESH_SECONDS", "0")

    app_factory = importlib.import_module("app.app_factory")
    app = app_factory.create_app()

    from app.db import SessionLocal
    from app.models import AuditEvent, Job, JobRun
    from app.services.jobs import create_job_with_runs, recover_stale_job_runs_for_agent
    from fastapi.testclient import TestClient

    old_started_at = datetime.now(timezone.utc) - timedelta(hours=2)

    with TestClient(app) as client:
        r = client.post(
            "/agent/register",
            json={
                "agent_id": "srv-stale",
                "hostname": "srv-stale",
                "fqdn": None,
                "os_id": "ubuntu",
                "os_version": "24.04",
                "kernel": "test",
                "labels": {"env": "test"},
            },
        )
        assert r.status_code == 200, r.text
        login = client.post("/auth/login", json={"username": "admin", "password": "admin-password-123"})
        assert login.status_code == 200, login.text
        csrf = client.cookies.get("fleet_csrf")
        headers = {"X-CSRF-Token": csrf} if csrf else {}

        with SessionLocal() as db:
            created = create_job_with_runs(
                db=db,
                job_type="query-pkg-version",
                payload={"packages": ["bash"]},
                agent_ids=["srv-stale"],
                commit=False,
            )
            db.flush()
            run = (
                db.execute(
                    select(JobRun)
                    .join(Job, Job.id == JobRun.job_id)
                    .where(Job.job_key == created.job_key, JobRun.agent_id == "srv-stale")
                )
                .scalar_one()
            )
            run.status = "running"
            run.started_at = old_started_at
            run.retry_count = 0
            db.commit()
            job_id = created.job_key

        detail_before = client.get(f"/jobs/{job_id}")
        assert detail_before.status_code == 200, detail_before.text
        before_run = detail_before.json()["runs"][0]
        assert before_run["retry_count"] == 0
        assert before_run["is_stale"] is True
        assert before_run["running_seconds"] >= 3600

        list_before = client.get("/jobs", params={"agent_id": "srv-stale", "limit": 10})
        assert list_before.status_code == 200, list_before.text
        list_item = next(it for it in list_before.json()["items"] if it["job_id"] == job_id)
        assert list_item["runs"]["stale_running"] == 1
        assert list_item["runs"]["retry_count_max"] == 0
        assert list_item["observability"]["age_seconds"] >= 0
        assert list_item["observability"]["is_old_queued"] is False

        with SessionLocal() as db:
            old_queued = create_job_with_runs(
                db=db,
                job_type="inventory-now",
                payload={"reason": "old-queue-test"},
                agent_ids=["srv-stale"],
                commit=False,
            )
            db.flush()
            old_job = db.execute(select(Job).where(Job.job_key == old_queued.job_key)).scalar_one()
            old_job.created_at = old_started_at
            db.commit()

        queued_list = client.get("/jobs", params={"agent_id": "srv-stale", "status": "queued", "limit": 10})
        assert queued_list.status_code == 200, queued_list.text
        old_item = next(it for it in queued_list.json()["items"] if it["job_id"] == old_queued.job_key)
        assert old_item["observability"]["age_seconds"] >= 3600
        assert old_item["observability"]["queued_warn_after_seconds"] == 1800
        assert old_item["observability"]["is_old_queued"] is True

        old_detail = client.get(f"/jobs/{old_queued.job_key}")
        assert old_detail.status_code == 200, old_detail.text
        assert old_detail.json()["observability"]["is_old_queued"] is True

        agent_health = client.get("/jobs/agent-health", params={"limit": 10})
        assert agent_health.status_code == 200, agent_health.text
        agent_health_item = next(it for it in agent_health.json()["items"] if it["agent_id"] == "srv-stale")
        assert agent_health_item["hostname"] == "srv-stale"
        assert agent_health_item["queued"] == 1
        assert agent_health_item["running"] == 1
        assert agent_health_item["stale_running"] == 1
        assert agent_health_item["oldest_queued_age_seconds"] >= 3600
        assert agent_health_item["oldest_queued_job_id"] == old_queued.job_key
        assert "inventory-now" in agent_health_item["types"]

        cancelled = client.post(f"/jobs/{old_queued.job_key}/cancel", headers=headers)
        assert cancelled.status_code == 200, cancelled.text
        assert cancelled.json()["cancelled_runs"] == 1
        old_detail_after_cancel = client.get(f"/jobs/{old_queued.job_key}")
        assert old_detail_after_cancel.status_code == 200, old_detail_after_cancel.text
        old_cancelled_run = old_detail_after_cancel.json()["runs"][0]
        assert old_cancelled_run["status"] == "failed"
        assert old_cancelled_run["exit_code"] == -1
        assert old_cancelled_run["error"] == "cancelled before agent claim"
        assert old_cancelled_run["is_cancelled"] is True
        cancelled_failed_runs = client.get("/dashboard/failed-runs", params={"hours": 24, "limit": 20})
        assert cancelled_failed_runs.status_code == 200, cancelled_failed_runs.text
        cancelled_failed_item = next(
            it for it in cancelled_failed_runs.json()["items"] if it["job_key"] == old_queued.job_key
        )
        assert cancelled_failed_item["is_cancelled"] is True
        cancelled_job_list = client.get("/jobs", params={"agent_id": "srv-stale", "status": "failed", "limit": 20})
        assert cancelled_job_list.status_code == 200, cancelled_job_list.text
        cancelled_job_item = next(it for it in cancelled_job_list.json()["items"] if it["job_id"] == old_queued.job_key)
        assert cancelled_job_item["runs"]["cancelled"] == 1

        r = client.get("/agent/next-job", params={"agent_id": "srv-stale"})
        assert r.status_code == 200, r.text
        job = r.json()["job"]
        assert job["job_id"] == job_id
        assert job["type"] == "query-pkg-version"
        assert job["packages"] == ["bash"]

        with SessionLocal() as db:
            run = (
                db.execute(
                    select(JobRun)
                    .join(Job, Job.id == JobRun.job_id)
                    .where(Job.job_key == job_id, JobRun.agent_id == "srv-stale")
                )
                .scalar_one()
            )
            assert run.status == "running"
            assert run.retry_count == 1
            assert run.started_at is not None
            assert run.error is None

        detail_after = client.get(f"/jobs/{job_id}")
        assert detail_after.status_code == 200, detail_after.text
        after_run = detail_after.json()["runs"][0]
        assert after_run["retry_count"] == 1
        assert after_run["is_stale"] is False
        assert after_run["running_seconds"] is not None

        with SessionLocal() as db:
            failed_job = create_job_with_runs(
                db=db,
                job_type="query-pkg-version",
                payload={"packages": ["coreutils"]},
                agent_ids=["srv-stale"],
                commit=False,
            )
            db.flush()
            failed_run = (
                db.execute(
                    select(JobRun)
                    .join(Job, Job.id == JobRun.job_id)
                    .where(Job.job_key == failed_job.job_key, JobRun.agent_id == "srv-stale")
                )
                .scalar_one()
            )
            failed_run.status = "running"
            failed_run.started_at = old_started_at
            failed_run.retry_count = 1
            result = recover_stale_job_runs_for_agent(db, "srv-stale")
            db.commit()
            assert result["failed"] >= 1
            assert failed_run.status == "failed"
            assert failed_run.finished_at is not None
            assert "stale running" in failed_run.error
            failed_job_id = failed_job.job_key
            failed_nonce = failed_run.job_nonce

        requeued = client.post(f"/jobs/{failed_job_id}/requeue", headers=headers)
        assert requeued.status_code == 200, requeued.text
        assert requeued.json()["status"] == "requeued"
        assert requeued.json()["requeued_runs"] == 1

        with SessionLocal() as db:
            requeued_run = (
                db.execute(
                    select(JobRun)
                    .join(Job, Job.id == JobRun.job_id)
                    .where(Job.job_key == failed_job_id, JobRun.agent_id == "srv-stale")
                )
                .scalar_one()
            )
            assert requeued_run.status == "queued"
            assert requeued_run.started_at is None
            assert requeued_run.finished_at is None
            assert requeued_run.exit_code is None
            assert requeued_run.error == "manual requeue requested"
            assert requeued_run.retry_count == 0
            assert requeued_run.job_nonce
            assert requeued_run.job_nonce != failed_nonce

            requeue_event = db.execute(
                select(AuditEvent)
                .where(AuditEvent.action == "jobs.requeue_failed", AuditEvent.target_id == failed_job_id)
                .order_by(AuditEvent.created_at.desc())
            ).scalar_one()
            assert requeue_event.meta["requeued_runs"] == 1

        requeued_list = client.get("/jobs", params={"agent_id": "srv-stale", "status": "queued", "limit": 20})
        assert requeued_list.status_code == 200, requeued_list.text
        assert any(it["job_id"] == failed_job_id for it in requeued_list.json()["items"])


def test_package_inventory_invalidates_host_cve_cache(monkeypatch):
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
    from app.models import Host, HostCVEStatus, HostPackage
    from fastapi.testclient import TestClient

    with TestClient(app) as client:
        r = client.post(
            "/agent/register",
            json={
                "agent_id": "srv-inventory-cve",
                "hostname": "srv-inventory-cve",
                "fqdn": None,
                "os_id": "ubuntu",
                "os_version": "24.04",
                "kernel": "test",
                "labels": {"env": "test"},
            },
        )
        assert r.status_code == 200, r.text

        with SessionLocal() as db:
            host = db.execute(select(Host).where(Host.agent_id == "srv-inventory-cve")).scalar_one()
            db.add(
                HostCVEStatus(
                    host_id=host.id,
                    cve="CVE-2025-32462",
                    affected=True,
                    checked_at=datetime.now(timezone.utc),
                    raw="stale vulnerable result",
                )
            )
            db.commit()

        inv = client.post(
            "/agent/inventory/packages",
            json={
                "agent_id": "srv-inventory-cve",
                "collected_at_unix": 1_700_000_000,
                "manager": "rpm",
                "packages": [
                    {"name": "libpam-modules", "version": "1.5.3-5ubuntu5.4", "arch": "x86_64"},
                ],
            },
        )
        assert inv.status_code == 200, inv.text

        with SessionLocal() as db:
            host = db.execute(select(Host).where(Host.agent_id == "srv-inventory-cve")).scalar_one()
            stale = db.execute(
                select(HostCVEStatus).where(
                    HostCVEStatus.host_id == host.id,
                    HostCVEStatus.cve == "CVE-2025-32462",
                )
            ).scalar_one_or_none()
            assert stale is None

            package = db.execute(
                select(HostPackage).where(
                    HostPackage.host_id == host.id,
                    HostPackage.name == "libpam-modules",
                )
            ).scalar_one_or_none()
            assert package is not None
            assert package.version == "1.5.3-5ubuntu5.4"
            assert package.arch == "x86_64"
            assert package.manager == "rpm"


def test_cleanup_offline_hosts_admin_only(monkeypatch):
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

    from datetime import datetime, timedelta, timezone

    from app.db import SessionLocal
    from app.models import AppUser, AppUserScope, Host
    from fastapi.testclient import TestClient

    with TestClient(app) as admin_client:
        rr = admin_client.post(
            "/agent/register",
            json={
                "agent_id": "srv-old",
                "hostname": "srv-old",
                "fqdn": None,
                "os_id": "ubuntu",
                "os_version": "24.04",
                "kernel": "test",
                "labels": {"env": "prod"},
            },
        )
        assert rr.status_code == 200, rr.text

        with SessionLocal() as db:
            h = db.execute(select(Host).where(Host.agent_id == "srv-old")).scalar_one()
            h.last_seen = datetime.now(timezone.utc) - timedelta(days=2)
            db.commit()

        lr = admin_client.post("/auth/login", json={"username": "admin", "password": "admin-password-123"})
        assert lr.status_code == 200, lr.text
        csrf = admin_client.cookies.get("fleet_csrf")
        headers = {"X-CSRF-Token": csrf} if csrf else {}

        reg = admin_client.post("/auth/register", json={"username": "viewer2", "password": "viewer-pass-123"}, headers=headers)
        assert reg.status_code == 200, reg.text

        with SessionLocal() as db:
            viewer = db.execute(select(AppUser).where(AppUser.username == "viewer2")).scalar_one()
            viewer.role = "readonly"
            db.add(AppUserScope(user_id=viewer.id, scope_type="label_selector", selector={"env": ["prod"]}))
            db.commit()

        ok = admin_client.post("/hosts/cleanup-offline?older_than_minutes=60&dry_run=true", headers=headers)
        assert ok.status_code == 200, ok.text
        payload = ok.json()
        assert int(payload.get("count") or 0) >= 1
        assert "srv-old" in (payload.get("agent_ids") or [])

    with TestClient(app) as viewer_client:
        lr2 = viewer_client.post("/auth/login", json={"username": "viewer2", "password": "viewer-pass-123"})
        assert lr2.status_code == 200, lr2.text
        viewer_csrf = viewer_client.cookies.get("fleet_csrf")
        viewer_headers = {"X-CSRF-Token": viewer_csrf} if viewer_csrf else {}

        denied = viewer_client.post("/hosts/cleanup-offline?older_than_minutes=60&dry_run=true", headers=viewer_headers)
        assert denied.status_code == 403, denied.text
