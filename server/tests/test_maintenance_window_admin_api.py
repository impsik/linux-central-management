from uuid import UUID

from sqlalchemy import select

from conftest import bootstrap_test_app, auth_client_factory


def test_admin_can_create_list_update_and_delete_maintenance_window(monkeypatch, auth_client_factory):
    app = bootstrap_test_app(monkeypatch, create_schema=True)

    from app.db import SessionLocal
    from app.models import AppMaintenanceWindow

    with auth_client_factory(app) as (client, headers):
        created = client.post(
            "/maintenance-windows",
            json={
                "name": "Prod patch window",
                "timezone": "UTC",
                "start_hhmm": "01:00",
                "end_hhmm": "05:00",
                "action_scope": ["dist-upgrade", "security-campaign"],
                "label_selector": {"env": "prod"},
                "enforcement_mode": "block",
                "enabled": True,
            },
            headers=headers,
        )
        assert created.status_code == 200, created.text
        created_body = created.json()
        assert created_body["name"] == "Prod patch window"
        assert created_body["label_selector"] == {"env": "prod"}
        assert created_body["action_scope"] == ["dist-upgrade", "security-campaign"]
        assert created_body["enabled"] is True
        assert created_body["id"]

        listed = client.get("/maintenance-windows", headers=headers)
        assert listed.status_code == 200, listed.text
        items = listed.json()["items"]
        assert len(items) == 1
        assert items[0]["id"] == created_body["id"]

        updated = client.put(
            f"/maintenance-windows/{created_body['id']}",
            json={
                "name": "Prod overnight window",
                "timezone": "Europe/Tallinn",
                "start_hhmm": "02:00",
                "end_hhmm": "06:00",
                "action_scope": ["dist-upgrade"],
                "label_selector": {"env": "prod", "team": "core"},
                "enforcement_mode": "block",
                "enabled": False,
            },
            headers=headers,
        )
        assert updated.status_code == 200, updated.text
        updated_body = updated.json()
        assert updated_body["name"] == "Prod overnight window"
        assert updated_body["timezone"] == "Europe/Tallinn"
        assert updated_body["action_scope"] == ["dist-upgrade"]
        assert updated_body["label_selector"] == {"env": "prod", "team": "core"}
        assert updated_body["enabled"] is False

        with SessionLocal() as db:
            row = db.execute(select(AppMaintenanceWindow).where(AppMaintenanceWindow.id == UUID(created_body["id"]))).scalar_one()
            assert row.name == "Prod overnight window"
            assert row.timezone == "Europe/Tallinn"
            assert row.enabled is False

        deleted = client.delete(f"/maintenance-windows/{created_body['id']}", headers=headers)
        assert deleted.status_code == 200, deleted.text
        assert deleted.json() == {"ok": True}

        listed_after = client.get("/maintenance-windows", headers=headers)
        assert listed_after.status_code == 200, listed_after.text
        assert listed_after.json()["items"] == []


def test_readonly_user_cannot_manage_maintenance_windows(monkeypatch, auth_client_factory):
    app = bootstrap_test_app(monkeypatch, create_schema=True)

    from app.db import SessionLocal
    from app.models import AppUser

    with auth_client_factory(app) as (client, headers):
        reg = client.post("/auth/register", json={"username": "viewer", "password": "viewer-pass-123"}, headers=headers)
        assert reg.status_code == 200, reg.text

        with SessionLocal() as db:
            user = db.execute(select(AppUser).where(AppUser.username == "viewer")).scalar_one()
            user.role = "readonly"
            db.commit()

    with auth_client_factory(app, username="viewer", password="viewer-pass-123") as (viewer_client, viewer_headers):
        resp = viewer_client.get("/maintenance-windows", headers=viewer_headers)
        assert resp.status_code == 403, resp.text


def test_admin_can_preview_maintenance_window_evaluation(monkeypatch, auth_client_factory):
    app = bootstrap_test_app(monkeypatch, create_schema=True)

    with auth_client_factory(app) as (client, headers):
        created = client.post(
            "/maintenance-windows",
            json={
                "name": "Prod patch window",
                "timezone": "UTC",
                "start_hhmm": "01:00",
                "end_hhmm": "05:00",
                "action_scope": ["dist-upgrade"],
                "label_selector": {"env": "prod"},
                "enforcement_mode": "block",
                "enabled": True,
            },
            headers=headers,
        )
        assert created.status_code == 200, created.text

        preview = client.post(
            "/maintenance-windows/evaluate",
            json={
                "action": "dist-upgrade",
                "labels": {"env": "prod"},
            },
            headers=headers,
        )
        assert preview.status_code == 200, preview.text
        body = preview.json()
        assert body["action"] == "dist-upgrade"
        assert body["matched_count"] == 1
        assert body["matched_windows"][0]["name"] == "Prod patch window"
        assert body["decision"] in {"allow", "block"}
        assert body["reason_code"] in {"within_scoped_window", "outside_scoped_window_blocked"}


def test_admin_preview_returns_no_matching_window_when_selector_does_not_match(monkeypatch, auth_client_factory):
    app = bootstrap_test_app(monkeypatch, create_schema=True)

    with auth_client_factory(app) as (client, headers):
        created = client.post(
            "/maintenance-windows",
            json={
                "name": "Prod patch window",
                "timezone": "UTC",
                "start_hhmm": "01:00",
                "end_hhmm": "05:00",
                "action_scope": ["dist-upgrade"],
                "label_selector": {"env": "prod"},
                "enforcement_mode": "block",
                "enabled": True,
            },
            headers=headers,
        )
        assert created.status_code == 200, created.text

        preview = client.post(
            "/maintenance-windows/evaluate",
            json={
                "action": "dist-upgrade",
                "labels": {"env": "stage"},
            },
            headers=headers,
        )
        assert preview.status_code == 200, preview.text
        body = preview.json()
        assert body["matched_count"] == 0
        assert body["decision"] == "allow"
        assert body["reason_code"] == "no_matching_scoped_window"
