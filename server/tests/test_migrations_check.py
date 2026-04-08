import importlib
import sys

from sqlalchemy import text


def _load_sqlite_app_db(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "sqlite+pysqlite:///:memory:")
    monkeypatch.setenv("BOOTSTRAP_USERNAME", "admin")
    monkeypatch.setenv("BOOTSTRAP_PASSWORD", "admin-...-123")
    monkeypatch.setenv("UI_COOKIE_SECURE", "false")
    monkeypatch.setenv("ALLOW_INSECURE_NO_AGENT_TOKEN", "true")
    monkeypatch.setenv("AGENT_SHARED_TOKEN", "")
    monkeypatch.setenv("DB_AUTO_CREATE_TABLES", "true")
    monkeypatch.setenv("DB_REQUIRE_MIGRATIONS_UP_TO_DATE", "false")
    monkeypatch.setenv("MFA_REQUIRE_FOR_PRIVILEGED", "false")

    for name in list(sys.modules):
        if name == "app" or name.startswith("app."):
            sys.modules.pop(name, None)

    db_mod = importlib.import_module("app.db")
    importlib.import_module("app.models")
    return db_mod


def test_assert_db_up_to_date_rejects_stamped_db_with_missing_tables(monkeypatch):
    db_mod = _load_sqlite_app_db(monkeypatch)
    from app.services import migrations_check

    monkeypatch.setattr(migrations_check, "_get_alembic_script_heads", lambda: {"head-rev"})

    db_mod.Base.metadata.create_all(bind=db_mod.engine)
    with db_mod.engine.begin() as conn:
        conn.execute(text("DROP TABLE cron_job_runs"))
        conn.execute(text("DROP TABLE cron_jobs"))
        conn.execute(text("CREATE TABLE alembic_version (version_num VARCHAR NOT NULL)"))
        conn.execute(text("INSERT INTO alembic_version (version_num) VALUES ('head-rev')"))

    try:
        migrations_check.assert_db_up_to_date(db_mod.engine)
        raise AssertionError("expected RuntimeError for missing tables")
    except RuntimeError as exc:
        msg = str(exc)
        assert "required tables are missing" in msg
        assert "cron_jobs" in msg


def test_assert_db_up_to_date_accepts_fully_created_schema(monkeypatch):
    db_mod = _load_sqlite_app_db(monkeypatch)
    from app.services import migrations_check

    monkeypatch.setattr(migrations_check, "_get_alembic_script_heads", lambda: {"head-rev"})

    db_mod.Base.metadata.create_all(bind=db_mod.engine)
    with db_mod.engine.begin() as conn:
        conn.execute(text("CREATE TABLE alembic_version (version_num VARCHAR NOT NULL)"))
        conn.execute(text("INSERT INTO alembic_version (version_num) VALUES ('head-rev')"))

    migrations_check.assert_db_up_to_date(db_mod.engine)
