import os
import importlib


def test_job_flow_sqlite(monkeypatch):
    # Configure test environment BEFORE importing app modules (engine is created at import time).
    monkeypatch.setenv("DATABASE_URL", "sqlite+pysqlite:///:memory:")
    monkeypatch.setenv("BOOTSTRAP_USERNAME", "admin")
    monkeypatch.setenv("BOOTSTRAP_PASSWORD", "admin-password-123")
    monkeypatch.setenv("UI_COOKIE_SECURE", "false")

    # Import after env is set
    app_factory = importlib.import_module("app.app_factory")

    app = app_factory.create_app()

    from fastapi.testclient import TestClient

    with TestClient(app) as client:
        # Monkeypatch ansible runner to avoid calling external ansible-playbook
        def fake_run_playbook(playbook, agent_ids, extra_vars):
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

        # Create a query job
        r = client.post("/jobs/pkg-query", json={"agent_ids": ["srv-001"], "packages": ["bash"]})
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
        from pathlib import Path
        ansible_logs_dir = Path("ansible/logs")
        ansible_logs_dir.mkdir(parents=True, exist_ok=True)
        (ansible_logs_dir / "test.log").write_text("hello log", encoding="utf-8")

        r = client.post("/ansible/run", json={"playbook": "noop.yml", "agent_ids": ["srv-001"], "extra_vars": {"secret": "x"}})
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
