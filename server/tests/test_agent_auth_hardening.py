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
