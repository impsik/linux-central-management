from pathlib import Path


def test_missing_runtime_tables_catchup_migration_exists():
    path = Path(__file__).resolve().parents[1] / 'alembic' / 'versions' / '20260419_01_missing_runtime_tables.py'
    src = path.read_text()

    assert 'revision = "20260419_01"' in src
    assert 'down_revision = "20260419_00"' in src
    for table in [
        'host_cve_status',
        'app_saved_views',
        'user_ssh_keys',
        'high_risk_action_requests',
        'ssh_key_deployment_requests',
        'notification_dedupe_state',
    ]:
        assert f'"{table}"' in src
