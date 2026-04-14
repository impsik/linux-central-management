from pathlib import Path


def test_cron_migration_exists_and_creates_tables():
    root = Path(__file__).resolve().parents[1]
    migration = root / "alembic" / "versions" / "20260414_00_cron_jobs.py"
    src = migration.read_text()

    assert 'revision = "20260414_00"' in src
    assert 'down_revision = "20260225_02"' in src
    assert '"cron_jobs"' in src
    assert '"cron_job_runs"' in src
    assert 'op.create_table(' in src



def test_startup_auto_create_imports_models_before_create_all():
    root = Path(__file__).resolve().parents[1]
    src = (root / "app" / "app_factory.py").read_text()

    import_line = 'import app.models  # ensure all model tables are registered in Base.metadata before create_all()'
    create_line = 'Base.metadata.create_all(bind=engine)'

    assert import_line in src
    assert create_line in src
    assert src.index(import_line) < src.index(create_line)
