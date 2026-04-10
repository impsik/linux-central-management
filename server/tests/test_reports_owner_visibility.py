from conftest import bootstrap_test_app, login_test_client


def test_hosts_updates_report_hides_unowned_hosts_for_regular_user(monkeypatch):
    app = bootstrap_test_app(monkeypatch, create_schema=True)

    from fastapi.testclient import TestClient
    from sqlalchemy import select
    import importlib

    with TestClient(app) as admin_client:
        headers = login_test_client(admin_client)

        for agent_id, owner in (("srv-tarmo", "tarmo"), ("srv-other", "other"), ("srv-unowned", None)):
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

        reg = admin_client.post("/auth/register", json={"username": "tarmo", "password": "tarmo-pass-123"}, headers=headers)
        assert reg.status_code == 200, reg.text

        db_mod = importlib.import_module("app.db")
        models = importlib.import_module("app.models")
        with db_mod.SessionLocal() as db:
            user = db.execute(select(models.AppUser).where(models.AppUser.username == "tarmo")).scalar_one()
            user.role = "readonly"
            db.commit()

    with TestClient(app) as user_client:
        login_test_client(user_client, username="tarmo", password="tarmo-pass-123")
        resp = user_client.get("/reports/hosts-updates?only_pending=false&online_only=false&sort=hostname&order=asc&limit=100")
        assert resp.status_code == 200, resp.text
        items = resp.json()["items"]
        agent_ids = [it["agent_id"] for it in items]
        assert agent_ids == ["srv-tarmo"]
