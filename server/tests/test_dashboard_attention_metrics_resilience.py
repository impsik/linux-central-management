from pathlib import Path


def test_dashboard_attention_rolls_back_after_best_effort_metrics_cache_failure():
    path = Path(__file__).resolve().parents[1] / 'app' / 'routers' / 'dashboard.py'
    src = path.read_text()

    assert 'Cache is best-effort. Roll back so a failed snapshot query does not poison the rest of the request.' in src
    assert 'db.rollback()' in src


def test_host_metrics_snapshots_migration_exists():
    path = Path(__file__).resolve().parents[1] / 'alembic' / 'versions' / '20260419_00_host_metrics_snapshots.py'
    src = path.read_text()

    assert 'revision = "20260419_00"' in src
    assert 'down_revision = "20260414_00"' in src
    assert 'op.create_table(' in src
    assert '"host_metrics_snapshots"' in src
