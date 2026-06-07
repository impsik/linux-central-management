import importlib


def test_shared_saved_views_are_visible_to_other_users(monkeypatch):
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

    with TestClient(app) as admin_client:
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

        personal = admin_client.post(
            "/auth/views",
            json={
                "scope": "hosts",
                "name": "Admin only",
                "payload": {"labelEnvFilter": "dev"},
                "is_shared": False,
            },
            headers=admin_headers,
        )
        assert personal.status_code == 200, personal.text

        shared = admin_client.post(
            "/auth/views",
            json={
                "scope": "hosts",
                "name": "Prod DBs",
                "payload": {"labelEnvFilter": "prod", "labelRoleFilter": "db"},
                "is_shared": True,
            },
            headers=admin_headers,
        )
        assert shared.status_code == 200, shared.text

        with TestClient(app) as user_client:
            login_user = user_client.post(
                "/auth/login",
                json={"username": "op1", "password": "pw-12345678"},
            )
            assert login_user.status_code == 200, login_user.text

            listed = user_client.get("/auth/views", params={"scope": "hosts"})
            assert listed.status_code == 200, listed.text
            assert listed.headers.get("Cache-Control") == "no-store"
            assert listed.headers.get("Vary") == "Cookie"
            items = listed.json().get("items") or []

            assert [it["name"] for it in items] == ["Prod DBs"]
            assert items[0]["is_shared"] is True
            assert items[0]["owner_username"] == "admin"
            assert items[0]["can_edit"] is False
