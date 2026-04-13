from conftest import bootstrap_test_app, auth_client_factory


def test_job_preflight_reports_package_db_health_failed_check(monkeypatch, auth_client_factory):
    app = bootstrap_test_app(monkeypatch, create_schema=True)

    from app.db import SessionLocal
    from app.models import Host

    with SessionLocal() as db:
        db.add(
            Host(
                agent_id='srv-brokenpkgdb',
                hostname='srv-brokenpkgdb',
                ip_address='10.0.0.31',
                os_id='ubuntu',
                os_version='24.04',
                kernel='test',
                labels={'env': 'prod'},
            )
        )
        db.commit()

    import app.routers.jobs as jobs_router
    monkeypatch.setattr(jobs_router, 'is_host_online', lambda *args, **kwargs: True)
    monkeypatch.setattr(jobs_router, '_probe_package_manager_lock', lambda db, agent_id: {'blocked': False, 'reason_code': 'apt_lock_clear', 'detail': 'No apt/dpkg lock detected'})
    monkeypatch.setattr(jobs_router, '_probe_disk_space', lambda db, agent_id: {'blocked': False, 'reason_code': 'disk_space_ok', 'detail': 'Root filesystem free space is within threshold', 'mountpoint': '/', 'avail_gb': 12.0, 'threshold_gb': 2.0, 'percent_used': 71.0})
    monkeypatch.setattr(
        jobs_router,
        '_probe_package_db_health',
        lambda db, agent_id: {
            'blocked': True,
            'reason_code': 'package_db_unhealthy',
            'detail': 'dpkg audit reported package database problems',
            'audit_summary': '2 packages not fully installed or removed',
        },
    )

    with auth_client_factory(app) as (client, headers):
        resp = client.post('/jobs/preflight', json={'action': 'dist-upgrade', 'agent_ids': ['srv-brokenpkgdb']}, headers=headers)
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body['blocked_by_preflight'] == ['srv-brokenpkgdb']
        pkgdb = next(item for item in body['failed_checks'] if item['kind'] == 'package_db_health')
        assert pkgdb['agent_id'] == 'srv-brokenpkgdb'
        assert pkgdb['severity'] == 'error'
        assert pkgdb['reason_code'] == 'package_db_unhealthy'
        assert pkgdb['detail'] == 'dpkg audit reported package database problems'
        assert pkgdb['meta']['audit_summary'] == '2 packages not fully installed or removed'
