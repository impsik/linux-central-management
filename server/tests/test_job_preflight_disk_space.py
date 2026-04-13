from conftest import bootstrap_test_app, auth_client_factory


def test_job_preflight_reports_disk_space_threshold_failed_check(monkeypatch, auth_client_factory):
    app = bootstrap_test_app(monkeypatch, create_schema=True)

    from app.db import SessionLocal
    from app.models import Host

    with SessionLocal() as db:
        db.add(
            Host(
                agent_id='srv-lowdisk',
                hostname='srv-lowdisk',
                ip_address='10.0.0.30',
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
    monkeypatch.setattr(
        jobs_router,
        '_probe_disk_space',
        lambda db, agent_id: {
            'blocked': True,
            'reason_code': 'disk_space_below_threshold',
            'detail': 'Root filesystem free space is below threshold',
            'mountpoint': '/',
            'avail_gb': 1.8,
            'threshold_gb': 2.0,
            'percent_used': 96.0,
        },
    )

    with auth_client_factory(app) as (client, headers):
        resp = client.post('/jobs/preflight', json={'action': 'dist-upgrade', 'agent_ids': ['srv-lowdisk']}, headers=headers)
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body['blocked_by_preflight'] == ['srv-lowdisk']
        disk = next(item for item in body['failed_checks'] if item['kind'] == 'disk_space')
        assert disk['agent_id'] == 'srv-lowdisk'
        assert disk['severity'] == 'error'
        assert disk['reason_code'] == 'disk_space_below_threshold'
        assert disk['detail'] == 'Root filesystem free space is below threshold'
        assert disk['meta']['mountpoint'] == '/'
        assert disk['meta']['avail_gb'] == 1.8
        assert disk['meta']['threshold_gb'] == 2.0
        assert disk['meta']['percent_used'] == 96.0
