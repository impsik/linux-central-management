from conftest import bootstrap_test_app, auth_client_factory


def test_owner_tagged_operator_can_control_owned_host(monkeypatch, auth_client_factory):
    monkeypatch.setenv('AGENT_ONLINE_GRACE_SECONDS', '3600')
    app = bootstrap_test_app(monkeypatch, create_schema=True)

    import app.routers.host_services as host_services_router
    import app.routers.host_users as host_users_router
    import app.routers.hosts as hosts_router

    monkeypatch.setattr(host_services_router, 'is_host_online', lambda *args, **kwargs: True)
    monkeypatch.setattr(host_users_router, 'is_host_online', lambda *args, **kwargs: True)
    monkeypatch.setattr(hosts_router, 'is_host_online', lambda *args, **kwargs: True)

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
        meta = owner_client.patch(
            '/hosts/srv-imre/metadata',
            json={'hostname': 'srv-imre-renamed', 'owner': 'imre'},
            headers=owner_headers,
        )
        assert meta.status_code == 200, meta.text
        assert meta.json()['host']['hostname'] == 'srv-imre-renamed'

        pkg = owner_client.post(
            '/hosts/srv-imre/packages/action',
            json={'action': 'upgrade', 'packages': ['bash']},
            headers=owner_headers,
        )
        assert pkg.status_code == 200, pkg.text
        assert pkg.json()['job_id']

        svc = owner_client.post(
            '/hosts/srv-imre/services/cron/restart?wait=false',
            headers=owner_headers,
        )
        assert svc.status_code == 200, svc.text
        assert svc.json()['job_id']

        usr = owner_client.post(
            '/hosts/srv-imre/users/alice/lock?wait=false',
            headers=owner_headers,
        )
        assert usr.status_code == 200, usr.text
        assert usr.json()['job_id']

        reboot = owner_client.post('/hosts/srv-imre/reboot', headers=owner_headers)
        assert reboot.status_code == 200, reboot.text
        assert reboot.json()['job_id']
