import os
import importlib
from fastapi import HTTPException
from sqlalchemy import select

from conftest import bootstrap_test_app, login_test_client


def test_job_flow_sqlite(monkeypatch):
    app = bootstrap_test_app(monkeypatch)

    from fastapi.testclient import TestClient

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
        headers = login_test_client(client)

        # Create a query job
        r = client.post("/jobs/pkg-query", json={"agent_ids": ["srv-001"], "packages": ["bash"]}, headers=headers)
        assert r.status_code == 200, r.text
        job_id = r.json()["job_id"]

        # Agent reports job running + success
        r = client.post(
            "/agent/job-event",
            json={"agent_id": "srv-001", "job_id": job_id, "status": "running"},
        )
        assert r.status_code == 200, r.text

        r = client.post(
            "/agent/job-event",
            json={
                "agent_id": "srv-001",
                "job_id": job_id,
                "status": "success",
                "exit_code": 0,
                "stdout": '{"packages":[{"name":"bash","version":"5.1","found":true}]}',
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
    app = bootstrap_test_app(monkeypatch)

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

        headers = login_test_client(admin_client)

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

        ev = admin_client.post(
            "/agent/job-event",
            json={
                "agent_id": "srv-dev",
                "job_id": job_id,
                "status": "success",
                "exit_code": 0,
                "stdout": '{"packages":[{"name":"bash","version":"5.1","found":true}]}',
            },
        )
        assert ev.status_code == 200, ev.text

    with TestClient(app) as viewer_client:
        viewer_headers = login_test_client(viewer_client, username="viewer", password="viewer-pass-123")

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


def test_cleanup_offline_hosts_admin_only(monkeypatch):
    app = bootstrap_test_app(monkeypatch)

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

        headers = login_test_client(admin_client)

        reg = admin_client.post("/auth/register", json={"username": "viewer2", "password": "viewer2-pass-123"}, headers=headers)
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
        viewer_headers = login_test_client(viewer_client, username="viewer2", password="viewer2-pass-123")

        denied = viewer_client.post("/hosts/cleanup-offline?older_than_minutes=60&dry_run=true", headers=viewer_headers)
        assert denied.status_code == 403, denied.text
