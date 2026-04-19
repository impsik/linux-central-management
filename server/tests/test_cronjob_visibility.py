import importlib
from datetime import datetime, timedelta, timezone


def test_admin_sees_all_cronjobs_and_regular_user_sees_only_own(monkeypatch):
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

    from fastapi.testclient import TestClient

    run_at = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()

    with TestClient(app) as admin_client:
        r = admin_client.post(
            "/agent/register",
            json={
                "agent_id": "srv-admin",
                "hostname": "srv-admin",
                "os_id": "ubuntu",
                "os_version": "24.04",
                "kernel": "test",
                "labels": {"owner": "admin"},
            },
        )
        assert r.status_code == 200, r.text

        r = admin_client.post(
            "/agent/register",
            json={
                "agent_id": "srv-op1",
                "hostname": "srv-op1",
                "os_id": "ubuntu",
                "os_version": "24.04",
                "kernel": "test",
                "labels": {"owner": "op1"},
            },
        )
        assert r.status_code == 200, r.text

        login_admin = admin_client.post(
            "/auth/login",
            json={"username": "admin", "password": "admin-password-123"},
        )
        assert login_admin.status_code == 200, login_admin.text
        csrf_admin = admin_client.cookies.get("fleet_csrf")
        admin_headers = {"X-CSRF-Token": csrf_admin} if csrf_admin else {}

        reg = admin_client.post(
            "/auth/register",
            json={"username": "op1", "password": "pw-12345678"},
            headers=admin_headers,
        )
        assert reg.status_code == 200, reg.text

        cron_admin = admin_client.post(
            "/cronjobs",
            json={
                "name": "admin inventory",
                "run_at": run_at,
                "action": "inventory-now",
                "agent_ids": ["srv-admin"],
                "schedule_kind": "once",
                "timezone": "UTC",
            },
            headers=admin_headers,
        )
        assert cron_admin.status_code == 200, cron_admin.text
        admin_cron_id = cron_admin.json()["id"]

        with TestClient(app) as user_client:
            login_user = user_client.post(
                "/auth/login",
                json={"username": "op1", "password": "pw-12345678"},
            )
            assert login_user.status_code == 200, login_user.text
            csrf_user = user_client.cookies.get("fleet_csrf")
            user_headers = {"X-CSRF-Token": csrf_user} if csrf_user else {}

            cron_user = user_client.post(
                "/cronjobs",
                json={
                    "name": "user inventory",
                    "run_at": run_at,
                    "action": "inventory-now",
                    "agent_ids": ["srv-op1"],
                    "schedule_kind": "once",
                    "timezone": "UTC",
                },
                headers=user_headers,
            )
            assert cron_user.status_code == 200, cron_user.text
            user_cron_id = cron_user.json()["id"]

            user_list = user_client.get("/cronjobs")
            assert user_list.status_code == 200, user_list.text
            user_items = user_list.json().get("items") or []
            assert {it["id"] for it in user_items} == {user_cron_id}
            assert all(it.get("owner_username") == "op1" for it in user_items)

        relogin_admin = admin_client.post(
            "/auth/login",
            json={"username": "admin", "password": "admin-password-123"},
        )
        assert relogin_admin.status_code == 200, relogin_admin.text

        admin_list = admin_client.get("/cronjobs")
        assert admin_list.status_code == 200, admin_list.text
        admin_items = admin_list.json().get("items") or []
        assert {it["id"] for it in admin_items} == {admin_cron_id, user_cron_id}
        owners = {it["id"]: it.get("owner_username") for it in admin_items}
        assert owners[admin_cron_id] == "admin"
        assert owners[user_cron_id] == "op1"
