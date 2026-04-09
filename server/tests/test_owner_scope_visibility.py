import importlib

from conftest import bootstrap_test_app, login_test_client


def test_non_admin_without_explicit_scopes_only_sees_owned_hosts(monkeypatch):
    app = bootstrap_test_app(monkeypatch, create_schema=True)

    from fastapi.testclient import TestClient
    from sqlalchemy import select

    with TestClient(app) as admin_client:
        headers = login_test_client(admin_client)

        for agent_id, owner in (("srv-alice", "alice"), ("srv-bob", "bob"), ("srv-shared", None)):
            labels = {"env": "prod"}
            if owner:
                labels["owner"] = owner
            r = admin_client.post(
                "/agent/register",
                json={
                    "agent_id": agent_id,
                    "hostname": agent_id,
                    "os_id": "ubuntu",
                    "os_version": "22.04",
                    "kernel": "test",
                    "labels": labels,
                },
            )
            assert r.status_code == 200, r.text

        reg = admin_client.post("/auth/register", json={"username": "alice", "password": "alice-pass-123"}, headers=headers)
        assert reg.status_code == 200, reg.text

        db_mod = importlib.import_module("app.db")
        models = importlib.import_module("app.models")
        with db_mod.SessionLocal() as db:
            user = db.execute(select(models.AppUser).where(models.AppUser.username == "alice")).scalar_one()
            user.role = "readonly"
            db.commit()

    with TestClient(app) as alice_client:
        login_test_client(alice_client, username="alice", password="alice-pass-123")
        resp = alice_client.get("/hosts?online_only=false")
        assert resp.status_code == 200, resp.text
        agent_ids = [h["agent_id"] for h in resp.json()]
        assert "srv-alice" in agent_ids
        assert "srv-bob" not in agent_ids
        assert "srv-shared" not in agent_ids


def test_explicit_scope_still_overrides_owner_fallback(monkeypatch):
    app = bootstrap_test_app(monkeypatch, create_schema=True)

    from fastapi.testclient import TestClient

    with TestClient(app) as admin_client:
        headers = login_test_client(admin_client)

        for agent_id, owner, env in (("srv-alice", "alice", "prod"), ("srv-dev", "bob", "dev")):
            r = admin_client.post(
                "/agent/register",
                json={
                    "agent_id": agent_id,
                    "hostname": agent_id,
                    "os_id": "ubuntu",
                    "os_version": "22.04",
                    "kernel": "test",
                    "labels": {"owner": owner, "env": env},
                },
            )
            assert r.status_code == 200, r.text

        reg = admin_client.post("/auth/register", json={"username": "alice", "password": "alice-pass-123"}, headers=headers)
        assert reg.status_code == 200, reg.text
        set_scope = admin_client.post(
            "/auth/admin/users/alice/scopes",
            json={"selectors": [{"env": ["dev"]}]},
            headers=headers,
        )
        assert set_scope.status_code == 200, set_scope.text

    with TestClient(app) as alice_client:
        login_test_client(alice_client, username="alice", password="alice-pass-123")
        resp = alice_client.get("/hosts?online_only=false")
        assert resp.status_code == 200, resp.text
        agent_ids = [h["agent_id"] for h in resp.json()]
        assert "srv-dev" in agent_ids
        assert "srv-alice" not in agent_ids
