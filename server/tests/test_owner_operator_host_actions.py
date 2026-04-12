from conftest import bootstrap_test_app, auth_client_factory


def test_owner_tagged_operator_can_queue_package_action(monkeypatch, auth_client_factory):
    app = bootstrap_test_app(monkeypatch, create_schema=True)

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
        resp = owner_client.post(
            '/hosts/srv-imre/packages/action',
            json={'action': 'upgrade', 'packages': ['bash']},
            headers=owner_headers,
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body['agent_id'] == 'srv-imre'
        assert body['action'] == 'upgrade'
        assert body['packages'] == ['bash']
        assert body['job_id']
