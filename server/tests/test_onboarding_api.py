from datetime import datetime, timedelta, timezone

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool


@pytest.fixture
def setup_api():
    from app.db import Base, get_db
    from app.deps import sha256_hex
    from app.models import AppSession, AppUser
    from app.routers.onboarding import router

    engine = create_engine('sqlite:///:memory:', connect_args={'check_same_thread': False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    db = Session(engine)
    for role in ('admin', 'operator', 'readonly'):
        user = AppUser(username=f'setup-{role}', password_hash='unused', role=role)
        db.add(user)
        db.flush()
        db.add(AppSession(user_id=user.id, token_sha256=sha256_hex(role), expires_at=datetime.now(timezone.utc) + timedelta(hours=1)))
    db.commit()
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_db] = lambda: db
    with TestClient(app) as client:
        yield client, db
    db.close()
    engine.dispose()


def test_onboarding_requires_admin(setup_api):
    client, _ = setup_api
    assert client.get('/onboarding/status').status_code == 401
    for role in ('operator', 'readonly'):
        client.cookies.set('fleet_session', role)
        assert client.get('/onboarding/status').status_code == 403
    client.cookies.set('fleet_session', 'admin')
    response = client.get('/onboarding/status')
    assert response.status_code == 200
    assert response.json() == {'host_count': 0, 'host': None}
    assert response.headers['cache-control'] == 'no-store'


def test_onboarding_reports_real_inventory_and_offline_state(setup_api):
    from app.models import Host, HostPackage, HostPackageUpdate
    client, db = setup_api
    client.cookies.set('fleet_session', 'admin')
    now = datetime.now(timezone.utc)
    host = Host(agent_id='first-agent', hostname='first', fqdn='first.example.test', ip_address='192.0.2.21',
                os_id='ubuntu', os_version='24.04', last_seen=now, agent_token_hash='must-not-be-exposed')
    db.add(host)
    db.commit()
    result = client.get('/onboarding/status').json()['host']
    assert result['online'] is True
    assert result['inventory_received'] is False
    assert result['package_count'] == 0
    assert 'agent_token_hash' not in result
    assert client.get('/onboarding/status?target=other-host').json()['host'] is None
    for target in ('FIRST', 'first.example.test', '192.0.2.21', 'first-agent'):
        assert client.get('/onboarding/status', params={'target': target}).json()['host']['agent_id'] == 'first-agent'
    db.add(HostPackage(host_id=host.id, name='bash', arch='amd64', version='5.2', manager='dpkg', collected_at=now))
    db.add(HostPackageUpdate(host_id=host.id, name='bash', update_available=True))
    host.last_seen = now - timedelta(hours=1)
    db.commit()
    result = client.get('/onboarding/status').json()['host']
    assert result['inventory_received'] is True
    assert result['package_count'] == result['updates_count'] == 1
    assert result['online'] is False
    assert result['inventory_at'] is not None


def test_onboarding_target_does_not_select_unrelated_host(setup_api):
    from app.models import Host
    client, db = setup_api
    client.cookies.set('fleet_session', 'admin')
    db.add_all([Host(agent_id='a', hostname='existing'), Host(agent_id='b', hostname='new-host')])
    db.commit()
    response = client.get('/onboarding/status?target=new-host')
    assert response.json()['host_count'] == 2
    assert response.json()['host']['agent_id'] == 'b'
    assert client.get('/onboarding/status', params={'target': "' OR 1=1 --"}).json()['host'] is None


def test_onboarding_keeps_application_mfa_gate(setup_api, monkeypatch):
    import app.db as db_module
    import app.app_factory as factory
    from app.config import settings
    _, db = setup_api
    monkeypatch.setattr(settings, 'mfa_require_for_privileged', True)
    monkeypatch.setattr(db_module, 'SessionLocal', lambda: Session(db.get_bind()))
    monkeypatch.setattr(factory, 'SessionLocal', lambda: Session(db.get_bind()))
    app = factory.create_app()
    # No lifespan: use the fixture database and avoid background services.
    client = TestClient(app)
    client.cookies.set('fleet_session', 'admin')
    response = client.get('/onboarding/status')
    assert response.status_code == 403
    assert response.json()['detail'] == 'MFA enrollment required'
    client.close()
