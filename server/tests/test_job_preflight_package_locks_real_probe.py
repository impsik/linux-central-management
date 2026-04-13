from conftest import bootstrap_test_app, auth_client_factory


def test_job_preflight_uses_package_lock_probe_for_online_targets(monkeypatch, auth_client_factory):
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

    calls = []

    def fake_probe(db, agent_id):
        calls.append(agent_id)
        return {
            'blocked': True,
            'reason_code': 'apt_lock_held',
            'detail': 'apt/dpkg lock appears to be held',
            'lock_holder': 'apt-get',
        }

    monkeypatch.setattr(jobs_router, '_probe_package_manager_lock', fake_probe)
    monkeypatch.setattr(
        jobs_router,
        '_probe_disk_space',
        lambda db, agent_id: {
            'blocked': False,
            'reason_code': 'disk_space_ok',
            'detail': 'Root filesystem free space is within threshold',
            'mountpoint': '/',
            'avail_gb': 12.0,
            'threshold_gb': 2.0,
            'percent_used': 71.0,
        },
    )
    monkeypatch.setattr(
        jobs_router,
        '_probe_package_db_health',
        lambda db, agent_id: {
            'blocked': False,
            'reason_code': 'package_db_ok',
            'detail': 'Package database health checks passed',
            'audit_summary': '',
        },
    )

    with auth_client_factory(app) as (client, headers):
        resp = client.post('/jobs/preflight', json={'action': 'dist-upgrade', 'agent_ids': ['srv-locked']}, headers=headers)
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert calls == ['srv-locked']
        pkg = next(item for item in body['failed_checks'] if item['kind'] == 'package_manager_lock')
        assert pkg['reason_code'] == 'apt_lock_held'
        assert pkg['meta']['lock_holder'] == 'apt-get'
