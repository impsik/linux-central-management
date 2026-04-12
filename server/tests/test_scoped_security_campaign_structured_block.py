from datetime import datetime, timedelta, timezone

from conftest import bootstrap_test_app, auth_client_factory


def test_security_campaign_returns_structured_scoped_window_block(monkeypatch, auth_client_factory):
    monkeypatch.setenv('MAINTENANCE_WINDOW_ENABLED', 'false')
    app = bootstrap_test_app(monkeypatch, create_schema=True)

    from app.db import SessionLocal
    from app.models import AppMaintenanceWindow, Host

    with SessionLocal() as db:
        db.add(
            Host(
                agent_id='srv-prod-002',
                hostname='srv-prod-002',
                ip_address='10.0.0.12',
                os_id='ubuntu',
                os_version='24.04',
                kernel='test',
                labels={'env': 'prod'},
            )
        )
        db.add(
            AppMaintenanceWindow(
                name='Prod security campaign window',
                timezone='UTC',
                start_hhmm='01:00',
                end_hhmm='02:00',
                action_scope=['security-campaign'],
                label_selector={'env': 'prod'},
                enforcement_mode='block',
                enabled=True,
            )
        )
        db.commit()

    import app.services.maintenance as maintenance
    monkeypatch.setattr(maintenance, '_is_within_window', lambda **kwargs: False)

    with auth_client_factory(app) as (client, headers):
        now = datetime.now(timezone.utc)
        resp = client.post(
            '/patching/campaigns/security-updates',
            json={
                'agent_ids': ['srv-prod-002'],
                'window_start': now.isoformat(),
                'window_end': (now + timedelta(hours=1)).isoformat(),
            },
            headers=headers,
        )
        assert resp.status_code == 403, resp.text
        body = resp.json()
        assert body['detail'] == "Action 'security-campaign' is blocked outside maintenance window for matching targets"
        assert body['reason_code'] == 'outside_scoped_window_blocked'
        assert body['action'] == 'security-campaign'
        assert body['matched_count'] == 1
        assert body['matched_windows'][0]['name'] == 'Prod security campaign window'
