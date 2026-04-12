from conftest import bootstrap_test_app, auth_client_factory


def test_dist_upgrade_returns_structured_scoped_window_block(monkeypatch, auth_client_factory):
    app = bootstrap_test_app(monkeypatch, create_schema=True)

    from app.db import SessionLocal
    from app.models import AppMaintenanceWindow, Host

    with SessionLocal() as db:
        db.add(
            Host(
                agent_id='srv-prod-001',
                hostname='srv-prod-001',
                ip_address='10.0.0.11',
                os_id='ubuntu',
                os_version='24.04',
                kernel='test',
                labels={'env': 'prod'},
            )
        )
        db.add(
            AppMaintenanceWindow(
                name='Prod dist-upgrade window',
                timezone='UTC',
                start_hhmm='01:00',
                end_hhmm='02:00',
                action_scope=['dist-upgrade'],
                label_selector={'env': 'prod'},
                enforcement_mode='block',
                enabled=True,
            )
        )
        db.commit()

    import app.services.maintenance as maintenance
    monkeypatch.setattr(maintenance, '_is_within_window', lambda **kwargs: False)

    with auth_client_factory(app) as (client, headers):
        resp = client.post('/jobs/dist-upgrade', json={'agent_ids': ['srv-prod-001']}, headers=headers)
        assert resp.status_code == 403, resp.text
        body = resp.json()
        assert body['detail'] == "Action 'dist-upgrade' is blocked outside maintenance window for matching targets"
        assert body['reason_code'] == 'outside_scoped_window_blocked'
        assert body['action'] == 'dist-upgrade'
        assert body['matched_count'] == 1
        assert body['matched_windows'][0]['name'] == 'Prod dist-upgrade window'
