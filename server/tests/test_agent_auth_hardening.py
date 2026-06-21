import importlib
import sys

from fastapi.routing import APIRoute
from fastapi.testclient import TestClient


def _reload_app_modules():
    for name in list(sys.modules.keys()):
        if name == 'app' or name.startswith('app.'):
            sys.modules.pop(name, None)


def _boot_app(monkeypatch, *, insecure_no_token: bool, token: str = '', allow_shared_runtime: bool = False):
    monkeypatch.setenv('DATABASE_URL', 'sqlite+pysqlite:///:memory:')
    monkeypatch.setenv('SERVER_BIND_HOST', '127.0.0.1')
    monkeypatch.setenv('BOOTSTRAP_PASSWORD', 'admin-password-123')
    monkeypatch.setenv('UI_COOKIE_SECURE', 'false')
    monkeypatch.setenv('ALLOW_INSECURE_NO_AGENT_TOKEN', 'true' if insecure_no_token else 'false')
    monkeypatch.setenv('AGENT_SHARED_TOKEN', token)
    monkeypatch.setenv('AGENT_SHARED_TOKEN_ALLOW_RUNTIME', 'true' if allow_shared_runtime else 'false')
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


def _register_agent(client, agent_id='srv-001', shared_token='shared-secret-123'):
    response = client.post(
        '/agent/register',
        json=_register_payload(agent_id),
        headers={'X-Fleet-Agent-Token': shared_token},
    )
    assert response.status_code == 200, response.text
    token = response.json().get('agent_token')
    assert token
    return token


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
        assert ok.json()['agent_token']

        db_mod = importlib.import_module('app.db')
        models = importlib.import_module('app.models')
        with db_mod.SessionLocal() as db:
            failures = db.query(models.AuditEvent).filter_by(action='agent.auth.failed').all()
            assert len(failures) >= 2


def test_agent_register_issues_per_agent_token(monkeypatch):
    app = _boot_app(monkeypatch, insecure_no_token=False, token='shared-secret-123')

    with TestClient(app, client=('192.168.100.50', 12345)) as client:
        reg = client.post(
            '/agent/register',
            json=_register_payload('srv-token'),
            headers={'X-Fleet-Agent-Token': 'shared-secret-123'},
        )
        assert reg.status_code == 200, reg.text
        agent_token = reg.json().get('agent_token')
        assert agent_token
        assert agent_token != 'shared-secret-123'

        hb = client.post(
            '/agent/heartbeat?agent_id=srv-token',
            headers={
                'X-Fleet-Agent-ID': 'srv-token',
                'X-Fleet-Agent-Token': agent_token,
            },
        )
        assert hb.status_code == 200, hb.text

        db_mod = importlib.import_module('app.db')
        models = importlib.import_module('app.models')
        agent_auth = importlib.import_module('app.services.agent_auth')
        with db_mod.SessionLocal() as db:
            host = db.query(models.Host).filter_by(agent_id='srv-token').one()
            assert host.agent_token_hash == agent_auth.hash_agent_token(agent_token)
            assert host.agent_token_hash != agent_token


def test_per_agent_token_cannot_claim_another_agent_id(monkeypatch):
    app = _boot_app(monkeypatch, insecure_no_token=False, token='shared-secret-123')

    with TestClient(app, client=('192.168.100.50', 12345)) as client:
        reg = client.post(
            '/agent/register',
            json=_register_payload('srv-bound'),
            headers={'X-Fleet-Agent-Token': 'shared-secret-123'},
        )
        assert reg.status_code == 200, reg.text
        agent_token = reg.json()['agent_token']

        denied = client.post(
            '/agent/heartbeat?agent_id=srv-other',
            headers={
                'X-Fleet-Agent-ID': 'srv-bound',
                'X-Fleet-Agent-Token': agent_token,
            },
        )
        assert denied.status_code == 403, denied.text
        assert 'agent token does not match agent_id' in denied.text


def test_per_agent_token_requires_agent_id_header(monkeypatch):
    app = _boot_app(monkeypatch, insecure_no_token=False, token='shared-secret-123')

    with TestClient(app, client=('192.168.100.50', 12345)) as client:
        reg = client.post(
            '/agent/register',
            json=_register_payload('srv-header'),
            headers={'X-Fleet-Agent-Token': 'shared-secret-123'},
        )
        assert reg.status_code == 200, reg.text
        agent_token = reg.json()['agent_token']

        denied = client.post(
            '/agent/heartbeat?agent_id=srv-header',
            headers={'X-Fleet-Agent-Token': agent_token},
        )
        assert denied.status_code == 401, denied.text


def test_shared_token_cannot_re_register_existing_bound_agent(monkeypatch):
    app = _boot_app(monkeypatch, insecure_no_token=False, token='shared-secret-123')

    with TestClient(app, client=('192.168.100.50', 12345)) as client:
        agent_token = _register_agent(client, 'srv-bound-existing')

        denied = client.post(
            '/agent/register',
            json=_register_payload('srv-bound-existing'),
            headers={'X-Fleet-Agent-Token': 'shared-secret-123'},
        )
        assert denied.status_code == 403, denied.text
        assert 'existing agent requires per-agent token' in denied.text

        ok = client.post(
            '/agent/register',
            json=_register_payload('srv-bound-existing'),
            headers={
                'X-Fleet-Agent-ID': 'srv-bound-existing',
                'X-Fleet-Agent-Token': agent_token,
            },
        )
        assert ok.status_code == 200, ok.text
        assert ok.json() == {'ok': True}


def test_shared_token_runtime_is_rejected_and_audited(monkeypatch):
    app = _boot_app(monkeypatch, insecure_no_token=False, token='shared-secret-123')

    with TestClient(app, client=('192.168.100.50', 12345)) as client:
        agent_token = _register_agent(client, 'known-agent')
        missing = client.post(
            '/agent/heartbeat?agent_id=missing-agent',
            headers={
                'X-Fleet-Agent-ID': 'known-agent',
                'X-Fleet-Agent-Token': agent_token,
            },
        )
        assert missing.status_code == 403, missing.text

        missing = client.post(
            '/agent/heartbeat?agent_id=missing-agent',
            headers={'X-Fleet-Agent-Token': 'shared-secret-123'},
        )
        assert missing.status_code == 403, missing.text

        # Shared-token runtime calls are rejected before handler-level unknown-agent auditing.
        db_mod = importlib.import_module('app.db')
        models = importlib.import_module('app.models')
        with db_mod.SessionLocal() as db:
            event = db.query(models.AuditEvent).filter_by(action='agent.auth.failed').order_by(models.AuditEvent.created_at.desc()).first()
            assert event.meta['reason'] == 'shared_token_not_allowed_for_runtime'


def test_shared_token_runtime_can_be_temporarily_allowed(monkeypatch):
    app = _boot_app(
        monkeypatch,
        insecure_no_token=False,
        token='shared-secret-123',
        allow_shared_runtime=True,
    )

    with TestClient(app, client=('192.168.100.50', 12345)) as client:
        _register_agent(client, 'missing-agent')
        missing = client.post(
            '/agent/heartbeat?agent_id=still-missing',
            headers={'X-Fleet-Agent-Token': 'shared-secret-123'},
        )
        assert missing.status_code == 404, missing.text

        db_mod = importlib.import_module('app.db')
        models = importlib.import_module('app.models')
        with db_mod.SessionLocal() as db:
            event = db.query(models.AuditEvent).filter_by(action='agent.unknown').one()
            assert event.target_id == 'still-missing'
            assert event.meta['agent_action'] == 'heartbeat'


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
        agent_token = ok.json()['agent_token']

        hb = client.post(
            '/agent/heartbeat?agent_id=srv-heartbeat-ip',
            headers={
                'X-Fleet-Agent-ID': 'srv-heartbeat-ip',
                'X-Fleet-Agent-Token': agent_token,
            },
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
