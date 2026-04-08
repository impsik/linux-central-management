def test_cve_sync_loop_interval_is_12h():
    from app.services.cve_sync import CVE_SYNC_INTERVAL_SECONDS

    assert CVE_SYNC_INTERVAL_SECONDS == 12 * 60 * 60
