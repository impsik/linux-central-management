from __future__ import annotations

import os
from pathlib import Path

from sqlalchemy import inspect, text
from sqlalchemy.engine import Engine


def _get_alembic_script_heads() -> set[str]:
    from alembic.config import Config
    from alembic.script import ScriptDirectory

    here = Path(__file__).resolve().parents[2]  # server/
    ini_path = here / "alembic.ini"
    cfg = Config(str(ini_path))
    # script_location is relative to ini
    script = ScriptDirectory.from_config(cfg)
    return set(script.get_heads())


def _get_db_revision(engine: Engine) -> str | None:
    # Read alembic_version.version_num if table exists.
    with engine.connect() as conn:
        dialect = conn.dialect.name
        if dialect == "postgresql":
            exists = conn.execute(
                text(
                    "SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name='alembic_version')"
                )
            ).scalar_one()
            if not exists:
                return None
        else:
            # SQLite
            try:
                exists = conn.execute(
                    text("SELECT name FROM sqlite_master WHERE type='table' AND name='alembic_version'")
                ).first()
                if not exists:
                    return None
            except Exception:
                return None

        row = conn.execute(text("SELECT version_num FROM alembic_version")).first()
        return row[0] if row else None


def _get_missing_model_tables(engine: Engine) -> list[str]:
    from ..db import Base

    existing = set(inspect(engine).get_table_names())
    expected = set(Base.metadata.tables.keys())
    return sorted(expected - existing)


def assert_db_up_to_date(engine: Engine) -> None:
    """Fail fast if alembic_version is missing or not at head."""

    heads = _get_alembic_script_heads()
    db_rev = _get_db_revision(engine)

    if db_rev is None:
        raise RuntimeError(
            "Database is not stamped with Alembic (missing alembic_version). "
            "Run: alembic upgrade head"
        )

    if db_rev not in heads:
        raise RuntimeError(
            f"Database Alembic revision {db_rev} is not at head {sorted(heads)}. "
            "Run: alembic upgrade head"
        )

    missing_tables = _get_missing_model_tables(engine)
    if missing_tables:
        preview = ", ".join(missing_tables[:10])
        if len(missing_tables) > 10:
            preview += f", ... (+{len(missing_tables) - 10} more)"
        raise RuntimeError(
            "Database is stamped at Alembic head but required tables are missing: "
            f"{preview}. Run: alembic upgrade head"
        )
