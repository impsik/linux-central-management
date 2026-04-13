from conftest import bootstrap_test_app, auth_client_factory


def test_job_preflight_reports_maintenance_window_blocks_for_risky_action(monkeypatch, auth_client_factory):
    monkeypatch.setenv('MAINTENANCE_WINDOW_ENABLED', 'false')
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
        resp = client.post('/jobs/preflight', json={'action': 'dist-upgrade', 'agent_ids': ['srv-prod-001']}, headers=headers)
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body['targeted_hosts'] == ['srv-prod-001']
        assert body['excluded_by_scope'] == []
        assert body['offline_or_unreachable'] == ['srv-prod-001']
        assert body['blocked_by_preflight'] == ['srv-prod-001']
        assert body['preflight_reason_code'] == 'outside_scoped_window_blocked'
        assert body['matched_windows'][0]['name'] == 'Prod dist-upgrade window'
        failed_checks = body['failed_checks']
        assert len(failed_checks) == 2
        kinds = {item['kind'] for item in failed_checks}
        assert 'offline_or_unreachable' in kinds
        assert 'maintenance_window' in kinds
        mw = next(item for item in failed_checks if item['kind'] == 'maintenance_window')
        assert mw['agent_id'] == 'srv-prod-001'
        assert mw['severity'] == 'error'
        assert mw['reason_code'] == 'outside_scoped_window_blocked'
        assert mw['matched_windows'][0]['name'] == 'Prod dist-upgrade window'
