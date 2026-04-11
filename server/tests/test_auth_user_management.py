import importlib

from conftest import bootstrap_test_app, login_test_client


def test_admin_can_register_readonly_user(monkeypatch):
    app = bootstrap_test_app(monkeypatch, create_schema=True)

    from fastapi.testclient import TestClient
    from sqlalchemy import select

    with TestClient(app) as client:
        headers = login_test_client(client)
        resp = client.post('/auth/register', json={'username': 'tarmo', 'password': 'tarmo-pass-123', 'role': 'readonly'}, headers=headers)
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body['role'] == 'readonly'

        db_mod = importlib.import_module('app.db')
        models = importlib.import_module('app.models')
        with db_mod.SessionLocal() as db:
            user = db.execute(select(models.AppUser).where(models.AppUser.username == 'tarmo')).scalar_one()
            assert user.role == 'readonly'


def test_user_can_change_own_password(monkeypatch):
    app = bootstrap_test_app(monkeypatch, create_schema=True)

    from fastapi.testclient import TestClient

    with TestClient(app) as admin_client:
        headers = login_test_client(admin_client)
        reg = admin_client.post('/auth/register', json={'username': 'tarmo', 'password': 'old-pass-123', 'role': 'readonly'}, headers=headers)
        assert reg.status_code == 200, reg.text

    with TestClient(app) as user_client:
        headers = login_test_client(user_client, username='tarmo', password='old-pass-123')
        resp = user_client.post('/auth/change-password', json={'current_password': 'old-pass-123', 'new_password': 'new-pass-456'}, headers=headers)
        assert resp.status_code == 200, resp.text

    with TestClient(app) as user_client2:
        login_test_client(user_client2, username='tarmo', password='new-pass-456')


def test_admin_can_remove_user(monkeypatch):
    app = bootstrap_test_app(monkeypatch, create_schema=True)

    from fastapi.testclient import TestClient
    from sqlalchemy import select

    with TestClient(app) as client:
        headers = login_test_client(client)
        reg = client.post('/auth/register', json={'username': 'tarmo', 'password': 'tarmo-pass-123', 'role': 'readonly'}, headers=headers)
        assert reg.status_code == 200, reg.text

        resp = client.post('/auth/users/tarmo/remove', headers=headers)
        assert resp.status_code == 200, resp.text
        assert resp.json()['removed'] is True

        users_after = client.get('/auth/admin/users')
        assert users_after.status_code == 200, users_after.text
        usernames_after = [str((it or {}).get('username') or '') for it in users_after.json().get('items', [])]
        assert 'tarmo' not in usernames_after

        db_mod = importlib.import_module('app.db')
        models = importlib.import_module('app.models')
        with db_mod.SessionLocal() as db:
            user = db.execute(select(models.AppUser).where(models.AppUser.username == 'tarmo')).scalar_one_or_none()
            assert user is None


def test_removed_user_cannot_log_in(monkeypatch):
    app = bootstrap_test_app(monkeypatch, create_schema=True)

    from fastapi.testclient import TestClient

    with TestClient(app) as client:
        headers = login_test_client(client)
        reg = client.post('/auth/register', json={'username': 'tarmo', 'password': 'tarmo-pass-123', 'role': 'readonly'}, headers=headers)
        assert reg.status_code == 200, reg.text

        resp = client.post('/auth/users/tarmo/remove', headers=headers)
        assert resp.status_code == 200, resp.text
        assert resp.json()['removed'] is True

    with TestClient(app) as removed_user_client:
        login_resp = removed_user_client.post('/auth/login', json={'username': 'tarmo', 'password': 'tarmo-pass-123'})
        assert login_resp.status_code == 401, login_resp.text
        assert 'Invalid username or password' in login_resp.text
