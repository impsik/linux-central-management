import asyncio
import importlib
import sys


def _reload_app_modules():
    for k in list(sys.modules.keys()):
        if k == "app" or k.startswith("app."):
            sys.modules.pop(k, None)


def _bootstrap_app(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "sqlite+pysqlite:///:memory:")
    monkeypatch.setenv("BOOTSTRAP_USERNAME", "admin")
    monkeypatch.setenv("BOOTSTRAP_PASSWORD", "admin-password-123")
    monkeypatch.setenv("MFA_REQUIRE_FOR_PRIVILEGED", "false")
    monkeypatch.setenv("ALLOW_INSECURE_NO_AGENT_TOKEN", "true")
    monkeypatch.setenv("DB_AUTO_CREATE_TABLES", "true")
    monkeypatch.setenv("DB_REQUIRE_MIGRATIONS_UP_TO_DATE", "false")
    _reload_app_modules()
    app_factory = importlib.import_module("app.app_factory")
    return app_factory.create_app()


def _register_host(client, agent_id: str, labels: dict | None = None):
    r = client.post(
        "/agent/register",
        json={
            "agent_id": agent_id,
            "hostname": agent_id,
            "fqdn": None,
            "os_id": "ubuntu",
            "os_version": "24.04",
            "kernel": "test",
            "labels": labels or {},
        },
    )
    assert r.status_code == 200, r.text


def _auth_headers(client) -> dict:
    lr = client.post("/auth/login", json={"username": "admin", "password": "admin-password-123"})
    assert lr.status_code == 200, lr.text
    csrf = client.cookies.get("fleet_csrf")
    return {"X-CSRF-Token": csrf} if csrf else {}


def _campaign_payload():
    return {
        "agent_ids": ["srv-001", "srv-002", "srv-003"],
        "rings": [
            {"name": "canary", "agent_ids": ["srv-001"]},
            {"name": "batch-1", "agent_ids": ["srv-002", "srv-003"]},
        ],
        "window_start": "2026-02-25T00:00:00Z",
        "window_end": "2026-02-26T00:00:00Z",
        "concurrency": 2,
        "rollout_controls": {
            "progressive": True,
            "auto_pause_enabled": True,
            "failure_threshold_percent": 50,
        },
    }


def test_rollout_pause_resume_and_approve_next(monkeypatch):
    app = _bootstrap_app(monkeypatch)
    from fastapi.testclient import TestClient

    with TestClient(app) as client:
        for aid in ["srv-001", "srv-002", "srv-003"]:
            _register_host(client, aid, labels={"env": "prod"})
        headers = _auth_headers(client)

        cr = client.post("/patching/campaigns/security-updates", json=_campaign_payload(), headers=headers)
        assert cr.status_code == 200, cr.text
        cid = cr.json()["campaign_id"]

        rr = client.get(f"/patching/campaigns/{cid}/rollout", headers=headers)
        assert rr.status_code == 200, rr.text
        data = rr.json()
        assert data["rollout"]["progressive"] is True
        assert data["rollout"]["approved_through_ring"] == 0

        an = client.post(f"/patching/campaigns/{cid}/approve-next", headers=headers)
        assert an.status_code == 200, an.text
        assert an.json()["rollout"]["approved_through_ring"] == 1

        pz = client.post(f"/patching/campaigns/{cid}/pause?reason=manual", headers=headers)
        assert pz.status_code == 200, pz.text
        assert pz.json()["rollout"]["paused"] is True

        rs = client.post(f"/patching/campaigns/{cid}/resume", headers=headers)
        assert rs.status_code == 200, rs.text
        assert rs.json()["rollout"]["paused"] is False


def test_auto_pause_on_failure_threshold(monkeypatch):
    app = _bootstrap_app(monkeypatch)
    from fastapi.testclient import TestClient

    with TestClient(app) as client:
        for aid in ["srv-001", "srv-002", "srv-003"]:
            _register_host(client, aid, labels={"env": "prod"})
        headers = _auth_headers(client)

        cr = client.post("/patching/campaigns/security-updates", json=_campaign_payload(), headers=headers)
        assert cr.status_code == 200, cr.text
        cid = cr.json()["campaign_id"]

        models = importlib.import_module("app.models")
        db_mod = importlib.import_module("app.db")
        patching_svc = importlib.import_module("app.services.patching")

        db = db_mod.SessionLocal()
        try:
            c = db.query(models.PatchCampaign).filter(models.PatchCampaign.campaign_key == cid).one()
            hosts = (
                db.query(models.PatchCampaignHost)
                .filter(models.PatchCampaignHost.campaign_id == c.id)
                .all()
            )
            # Force canary ring to completed with 50% failure rate.
            for h in hosts:
                if h.ring == 0:
                    h.status = "failed" if h.agent_id == "srv-001" else "success"
                else:
                    h.status = "queued"
            db.commit()

            asyncio.run(patching_svc._advance_campaign(db, c))
            db.commit()
            db.refresh(c)
            meta = c.rollout_meta or {}
            assert bool(meta.get("paused")) is True
            assert "failure threshold" in str(meta.get("pause_reason") or "").lower()
            assert meta.get("paused_by") == "system"
        finally:
            db.close()
