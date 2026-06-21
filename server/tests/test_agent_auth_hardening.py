import importlib
import sys

from fastapi.routing import APIRoute
from fastapi.testclient import TestClient


def _reload_app_modules():
    for name in list(sys.modules.keys()):
        if name == 'app' or name.startswith('app.'):
            sys.modules.pop(name, None)


def _boot_app(monkeypatch, *, insecure_no_token: bool, token: str = ''):
    monkeypatch.setenv('DATABASE_URL', 'sqlite+pysqlite:///:memory:')
    monkeypatch.setenv('SERVER_BIND_HOST', '127.0.0.1')
    monkeypatch.setenv('BOOTSTRAP_PASSWORD', 'admin-password-123')
    monkeypatch.setenv('UI_COOKIE_SECURE', 'false')
    monkeypatch.setenv('ALLOW_INSECURE_NO_AGENT_TOKEN', 'true' if insecure_no_token else 'false')
    monkeypatch.setenv('AGENT_SHARED_TOKEN', token)
    monkeypatch.setenv('DB_AUTO_CREATE_TABLES', 'true')
    monkeypatch.setenv('DB_REQUIRE_MIGRATIONS_UP_TO_DATE', 'false')
    monkeypatch.setenv('MFA_REQUIRE_FOR_PRIVILEGED', 'false')
    _reload_app_modules()
    app_factory = importlib.import_module('app.app_factory')
    return app_factory.create_app()


def _register_payload(agent_id='srv-001'):
    return {
        'agent_id': agent_id,
        'hostname': agent_id,
        'fqdn': f'{agent_id}.example.test',
        'os_id': 'ubuntu',
        'os_version': '24.04',
        'kernel': '6.8.0',
        'labels': {'env': 'test'},
    }


def test_insecure_no_token_mode_is_loopback_only(monkeypatch):
    app = _boot_app(monkeypatch, insecure_no_token=True, token='')

    with TestClient(app, client=('192.168.100.50', 12345)) as remote_client:
        r = remote_client.post('/agent/register', json=_register_payload())
        assert r.status_code == 401, r.text
        assert 'Agent token required' in r.text

    with TestClient(app) as loopback_client:
        r = loopback_client.post('/agent/register', json=_register_payload('srv-local'))
        assert r.status_code == 200, r.text
        assert r.json()['ok'] is True


def test_agent_routes_require_token_when_configured(monkeypatch):
    app = _boot_app(monkeypatch, insecure_no_token=False, token='shared-secret-123')

    with TestClient(app, client=('192.168.100.50', 12345)) as client:
        no_token = client.post('/agent/register', json=_register_payload())
        assert no_token.status_code == 401, no_token.text

        wrong_token = client.post(
            '/agent/register',
            json=_register_payload('srv-wrong'),
            headers={'X-Fleet-Agent-Token': 'wrong'},
        )
        assert wrong_token.status_code == 401, wrong_token.text

        ok = client.post(
            '/agent/register',
            json=_register_payload('srv-good'),
            headers={'X-Fleet-Agent-Token': 'shared-secret-123'},
        )
        assert ok.status_code == 200, ok.text
        assert ok.json()['ok'] is True


def test_each_agent_route_rejects_missing_token_when_configured(monkeypatch):
    app = _boot_app(monkeypatch, insecure_no_token=False, token='shared-secret-123')

    requests = [
        ('post', '/agent/register', {'json': _register_payload()}),
        ('post', '/agent/heartbeat?agent_id=srv-001', {}),
        (
            'post',
            '/agent/inventory/packages',
            {'json': {'agent_id': 'srv-001', 'collected_at_unix': 1_700_000_000, 'packages': []}},
        ),
        (
            'post',
            '/agent/inventory/package-updates',
            {'json': {'agent_id': 'srv-001', 'checked_at_unix': 1_700_000_000, 'updates': []}},
        ),
        ('get', '/agent/next-job?agent_id=srv-001', {}),
        (
            'post',
            '/agent/job-event',
            {'json': {'agent_id': 'srv-001', 'job_id': 'job-001', 'status': 'running'}},
        ),
    ]

    with TestClient(app, client=('192.168.100.50', 12345)) as client:
        for method, path, kwargs in requests:
            response = getattr(client, method)(path, **kwargs)
            assert response.status_code == 401, f'{method.upper()} {path}: {response.text}'


def test_agent_register_prefers_reported_guest_ip_over_request_peer(monkeypatch):
    app = _boot_app(monkeypatch, insecure_no_token=False, token='shared-secret-123')

    with TestClient(app, client=('192.168.100.1', 12345)) as client:
        payload = _register_payload('srv-ip')
        payload['ip_addresses'] = ['127.0.0.1', '192.16.1.25']
        ok = client.post(
            '/agent/register',
            json=payload,
            headers={'X-Fleet-Agent-Token': 'shared-secret-123'},
        )
        assert ok.status_code == 200, ok.text

        db_mod = importlib.import_module('app.db')
        models = importlib.import_module('app.models')
        with db_mod.SessionLocal() as db:
            host = db.query(models.Host).filter_by(agent_id='srv-ip').one()
            assert host.ip_address == '192.16.1.25'


def test_agent_heartbeat_does_not_clobber_reported_guest_ip(monkeypatch):
    app = _boot_app(monkeypatch, insecure_no_token=False, token='shared-secret-123')

    with TestClient(app, client=('192.168.100.1', 12345)) as client:
        payload = _register_payload('srv-heartbeat-ip')
        payload['ip_addresses'] = ['192.16.1.26']
        ok = client.post(
            '/agent/register',
            json=payload,
            headers={'X-Fleet-Agent-Token': 'shared-secret-123'},
        )
        assert ok.status_code == 200, ok.text

        hb = client.post(
            '/agent/heartbeat?agent_id=srv-heartbeat-ip',
            headers={'X-Fleet-Agent-Token': 'shared-secret-123'},
        )
        assert hb.status_code == 200, hb.text

        db_mod = importlib.import_module('app.db')
        models = importlib.import_module('app.models')
        with db_mod.SessionLocal() as db:
            host = db.query(models.Host).filter_by(agent_id='srv-heartbeat-ip').one()
            assert host.ip_address == '192.16.1.26'


def test_all_agent_routes_have_router_level_auth_dependency(monkeypatch):
    app = _boot_app(monkeypatch, insecure_no_token=True, token='')
    agent_auth = importlib.import_module('app.services.agent_auth')

    agent_routes = [
        route for route in app.routes
        if isinstance(route, APIRoute) and route.path.startswith('/agent/')
    ]
    assert agent_routes, 'expected at least one /agent route'

    for route in agent_routes:
        dep_calls = [getattr(dep, 'call', None) for dep in route.dependant.dependencies]
        assert agent_auth.require_agent_token_dep in dep_calls, f'missing agent auth dependency on {route.path}'
