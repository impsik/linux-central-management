from conftest import bootstrap_test_app, auth_client_factory


def test_job_preflight_reports_package_manager_lock_failed_check(monkeypatch, auth_client_factory):
    app = bootstrap_test_app(monkeypatch, create_schema=True)

    from app.db import SessionLocal
    from app.models import Host

    with SessionLocal() as db:
        db.add(
            Host(
                agent_id='srv-locked',
                hostname='srv-locked',
                ip_address='10.0.0.20',
                os_id='ubuntu',
                os_version='24.04',
                kernel='test',
                labels={'env': 'prod'},
            )
        )
        db.commit()

    import app.routers.jobs as jobs_router
    monkeypatch.setattr(jobs_router, 'is_host_online', lambda *args, **kwargs: True)
    monkeypatch.setattr(
        jobs_router,
        '_probe_package_manager_lock',
        lambda db, agent_id: {
            'blocked': agent_id == 'srv-locked',
            'reason_code': 'apt_lock_held',
            'detail': 'apt/dpkg lock appears to be held',
            'lock_holder': 'apt-get',
        },
    )

    with auth_client_factory(app) as (client, headers):
        resp = client.post('/jobs/preflight', json={'action': 'dist-upgrade', 'agent_ids': ['srv-locked']}, headers=headers)
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body['blocked_by_preflight'] == ['srv-locked']
        failed_checks = body['failed_checks']
        pkg = next(item for item in failed_checks if item['kind'] == 'package_manager_lock')
        assert pkg['agent_id'] == 'srv-locked'
        assert pkg['severity'] == 'error'
        assert pkg['reason_code'] == 'apt_lock_held'
        assert pkg['detail'] == 'apt/dpkg lock appears to be held'
        assert pkg['meta']['lock_holder'] == 'apt-get'
