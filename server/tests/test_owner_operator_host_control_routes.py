from conftest import bootstrap_test_app, auth_client_factory


def _boot_owned_host_app(monkeypatch):
    monkeypatch.setenv('AGENT_ONLINE_GRACE_SECONDS', '3600')
    app = bootstrap_test_app(monkeypatch, create_schema=True)

    import app.routers.host_services as host_services_router
    import app.routers.host_users as host_users_router
    import app.routers.hosts as hosts_router

    monkeypatch.setattr(host_services_router, 'is_host_online', lambda *args, **kwargs: True)
    monkeypatch.setattr(host_users_router, 'is_host_online', lambda *args, **kwargs: True)
    monkeypatch.setattr(hosts_router, 'is_host_online', lambda *args, **kwargs: True)
    return app


def _seed_owned_operator(app, auth_client_factory):
    with auth_client_factory(app) as (admin_client, headers):
        host_resp = admin_client.post(
            '/agent/register',
            json={
                'agent_id': 'srv-imre',
                'hostname': 'srv-imre',
                'ip_address': '10.0.0.5',
                'os_id': 'ubuntu',
                'os_version': '22.04',
                'kernel': 'test',
                'labels': {'owner': 'imre'},
            },
        )
        assert host_resp.status_code == 200, host_resp.text

        user_resp = admin_client.post(
            '/auth/register',
            json={'username': 'imre', 'password': 'imre-pass-123', 'role': 'operator'},
            headers=headers,
        )
        assert user_resp.status_code == 200, user_resp.text

    with auth_client_factory(app, username='imre', password='imre-pass-123') as (owner_client, owner_headers):
        heartbeat = owner_client.post('/agent/heartbeat', params={'agent_id': 'srv-imre'})
        assert heartbeat.status_code == 200, heartbeat.text
        return owner_client, owner_headers


def test_owner_tagged_operator_can_update_owned_host_metadata(monkeypatch, auth_client_factory):
    app = _boot_owned_host_app(monkeypatch)
    owner_client, owner_headers = _seed_owned_operator(app, auth_client_factory)

    resp = owner_client.patch(
        '/hosts/srv-imre/metadata',
        json={'hostname': 'srv-imre-renamed', 'owner': 'imre', 'role': 'app'},
        headers=owner_headers,
    )

    assert resp.status_code == 200, resp.text
    body = resp.json()['host']
    assert body['hostname'] == 'srv-imre-renamed'
    assert body['labels']['owner'] == 'imre'
    assert body['labels']['role'] == 'app'


def test_owner_tagged_operator_can_restart_services_on_owned_host(monkeypatch, auth_client_factory):
    app = _boot_owned_host_app(monkeypatch)
    owner_client, owner_headers = _seed_owned_operator(app, auth_client_factory)

    resp = owner_client.post(
        '/hosts/srv-imre/services/cron/restart?wait=false',
        headers=owner_headers,
    )

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body['status'] == 'queued'
    assert body['job_id']


def test_owner_tagged_operator_can_reboot_owned_host(monkeypatch, auth_client_factory):
    app = _boot_owned_host_app(monkeypatch)
    owner_client, owner_headers = _seed_owned_operator(app, auth_client_factory)

    resp = owner_client.post('/hosts/srv-imre/reboot', headers=owner_headers)

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body['job_id']
    assert body['agent_id'] == 'srv-imre'


def test_owner_tagged_operator_can_lock_and_unlock_users_on_owned_host(monkeypatch, auth_client_factory):
    app = _boot_owned_host_app(monkeypatch)
    owner_client, owner_headers = _seed_owned_operator(app, auth_client_factory)

    lock_resp = owner_client.post('/hosts/srv-imre/users/alice/lock?wait=false', headers=owner_headers)
    assert lock_resp.status_code == 200, lock_resp.text
    assert lock_resp.json()['status'] == 'queued'
    assert lock_resp.json()['job_id']

    unlock_resp = owner_client.post('/hosts/srv-imre/users/alice/unlock?wait=false', headers=owner_headers)
    assert unlock_resp.status_code == 200, unlock_resp.text
    assert unlock_resp.json()['status'] == 'queued'
    assert unlock_resp.json()['job_id']


def test_owner_tagged_operator_can_check_package_updates_on_owned_host(monkeypatch, auth_client_factory):
    app = _boot_owned_host_app(monkeypatch)
    owner_client, owner_headers = _seed_owned_operator(app, auth_client_factory)

    resp = owner_client.post('/hosts/srv-imre/packages/check-updates?refresh=true&wait=false', headers=owner_headers)

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body['status'] == 'queued'
    assert body['job_id']


def test_owner_tagged_operator_can_refresh_package_inventory_on_owned_host(monkeypatch, auth_client_factory):
    app = _boot_owned_host_app(monkeypatch)
    owner_client, owner_headers = _seed_owned_operator(app, auth_client_factory)

    resp = owner_client.post('/hosts/srv-imre/packages/refresh?wait=false', headers=owner_headers)

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body['status'] == 'queued'
    assert body['job_id']


def test_owner_reassignment_removes_previous_owner_access(monkeypatch, auth_client_factory):
    app = _boot_owned_host_app(monkeypatch)
    owner_client, owner_headers = _seed_owned_operator(app, auth_client_factory)

    reassign = owner_client.patch(
        '/hosts/srv-imre/metadata',
        json={'owner': 'alice'},
        headers=owner_headers,
    )
    assert reassign.status_code == 200, reassign.text
    assert reassign.json()['host']['labels']['owner'] == 'alice'

    hosts_resp = owner_client.get('/hosts', headers=owner_headers)
    assert hosts_resp.status_code == 200, hosts_resp.text
    hosts = hosts_resp.json()
    assert all(h['agent_id'] != 'srv-imre' for h in hosts)

    denied = owner_client.post('/hosts/srv-imre/packages/refresh?wait=false', headers=owner_headers)
    assert denied.status_code == 404, denied.text
