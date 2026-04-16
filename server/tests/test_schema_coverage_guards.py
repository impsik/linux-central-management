from pathlib import Path
import re


def _model_tables(root: Path) -> list[str]:
    models = (root / "app" / "models.py").read_text()
    return sorted(set(re.findall(r'__tablename__\s*=\s*"([^"]+)"', models)))



def _migration_created_tables(root: Path) -> set[str]:
    text = "\n".join(p.read_text(errors="ignore") for p in (root / "alembic" / "versions").glob("*.py"))
    tables = set(re.findall(r'create_table\(\s*["\']([^"\']+)["\']', text))
    tables |= set(re.findall(r'CREATE TABLE IF NOT EXISTS\s+([a-zA-Z_][a-zA-Z0-9_]*)', text))
    return tables



def test_all_model_tables_have_migration_coverage():
    root = Path(__file__).resolve().parents[1]
    model_tables = _model_tables(root)
    created_tables = _migration_created_tables(root)
    missing = [table for table in model_tables if table not in created_tables]
    assert missing == []



def test_docker_server_runs_alembic_before_uvicorn():
    dockerfile = Path(__file__).resolve().parents[2] / "server" / "Dockerfile"
    src = dockerfile.read_text()
    assert "alembic upgrade head && exec uvicorn app.main:app" in src
