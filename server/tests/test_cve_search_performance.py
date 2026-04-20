import importlib
import sys
from datetime import datetime, timezone
from pathlib import Path

from fastapi.testclient import TestClient


def _reload_app_modules():
    for name in list(sys.modules.keys()):
        if name == 'app' or name.startswith('app.'):
            sys.modules.pop(name, None)


def _boot_app(monkeypatch):
    monkeypatch.setenv('DATABASE_URL', 'sqlite+pysqlite:///:memory:')
    monkeypatch.setenv('BOOTSTRAP_PASSWORD', 'admin-password-123')
    monkeypatch.setenv('UI_COOKIE_SECURE', 'false')
    monkeypatch.setenv('ALLOW_INSECURE_NO_AGENT_TOKEN', 'true')
    monkeypatch.setenv('AGENT_SHARED_TOKEN', '')
    monkeypatch.setenv('DB_AUTO_CREATE_TABLES', 'true')
    monkeypatch.setenv('DB_REQUIRE_MIGRATIONS_UP_TO_DATE', 'false')
    monkeypatch.setenv('MFA_REQUIRE_FOR_PRIVILEGED', 'false')
    _reload_app_modules()
    app_factory = importlib.import_module('app.app_factory')
    app = app_factory.create_app()
    db_mod = importlib.import_module('app.db')
    models = importlib.import_module('app.models')
    return app, db_mod.SessionLocal, models


def _register_host(client, agent_id: str, owner: str):
    r = client.post(
        '/agent/register',
        json={
            'agent_id': agent_id,
            'hostname': agent_id,
            'fqdn': f'{agent_id}.example.test',
            'os_id': 'ubuntu',
            'os_version': '24.04',
            'kernel': '6.8.0',
            'labels': {'owner': owner},
        },
    )
    assert r.status_code == 200, r.text


def _login(client, username: str, password: str):
    r = client.post('/auth/login', json={'username': username, 'password': password})
    assert r.status_code == 200, r.text
    csrf = client.cookies.get('fleet_csrf')
    return {'X-CSRF-Token': csrf} if csrf else {}


def test_cve_search_filters_visibility_without_full_host_scan_fallback(monkeypatch):
    app, SessionLocal, models = _boot_app(monkeypatch)

    with TestClient(app) as admin_client:
        _register_host(admin_client, 'srv-op1', 'op1')
        _register_host(admin_client, 'srv-alice', 'alice')
        _register_host(admin_client, 'srv-other-cve', 'alice')

        admin_headers = _login(admin_client, 'admin', 'admin-password-123')
        reg = admin_client.post(
            '/auth/register',
            json={'username': 'op1', 'password': 'pw-12345678'},
            headers=admin_headers,
        )
        assert reg.status_code == 200, reg.text

        with SessionLocal() as db:
            hosts = {h.agent_id: h for h in db.execute(importlib.import_module('sqlalchemy').select(models.Host)).scalars().all()}
            db.add(models.HostCVEStatus(
                host_id=hosts['srv-op1'].id,
                cve='CVE-2026-9999',
                affected=True,
                summary='owned host affected',
                checked_at=datetime.now(timezone.utc),
            ))
            db.add(models.HostCVEStatus(
                host_id=hosts['srv-alice'].id,
                cve='CVE-2026-9999',
                affected=True,
                summary='foreign host affected',
                checked_at=datetime.now(timezone.utc),
            ))
            db.add(models.HostCVEStatus(
                host_id=hosts['srv-other-cve'].id,
                cve='CVE-2026-1234',
                affected=True,
                summary='different cve',
                checked_at=datetime.now(timezone.utc),
            ))
            db.commit()

        admin_search = admin_client.get('/search/cve', params={'cve': 'CVE-2026-9999'})
        assert admin_search.status_code == 200, admin_search.text
        admin_ids = {row['agent_id'] for row in admin_search.json()}
        assert admin_ids == {'srv-op1', 'srv-alice'}

        with TestClient(app) as op1_client:
            _login(op1_client, 'op1', 'pw-12345678')
            op1_search = op1_client.get('/search/cve', params={'cve': 'CVE-2026-9999'})
            assert op1_search.status_code == 200, op1_search.text
            assert op1_search.json() == [
                {
                    'hostname': 'srv-op1',
                    'agent_id': 'srv-op1',
                    'affected': True,
                    'checked_at': op1_search.json()[0]['checked_at'],
                }
            ]


def test_host_cve_search_index_migration_exists():
    path = Path(__file__).resolve().parents[1] / 'alembic' / 'versions' / '20260420_00_host_cve_search_indexes.py'
    src = path.read_text()

    assert 'CREATE INDEX IF NOT EXISTS ix_host_cve_status_cve ON host_cve_status (cve)' in src
    assert 'CREATE INDEX IF NOT EXISTS ix_host_cve_status_cve_affected ON host_cve_status (cve, affected)' in src
