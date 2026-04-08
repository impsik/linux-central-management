import os
import sys
import importlib
from contextlib import contextmanager
from pathlib import Path

import pytest

# Ensure the server/ directory is on sys.path so `import app.*` works in all runners.
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

REPO_ROOT = ROOT.parent
TEMPLATES_DIR = ROOT / "app" / "templates"
TEST_BOOTSTRAP_USERNAME = "admin"
TEST_BOOTSTRAP_PASSWORD = "admin-password-123"

# Test-suite guardrails:
# CI workflow exports production-like env defaults globally for backend jobs.
# SQLite tests in this suite require local in-memory bootstrap behavior instead.
os.environ["DB_AUTO_CREATE_TABLES"] = "true"
os.environ["DB_REQUIRE_MIGRATIONS_UP_TO_DATE"] = "false"
os.environ["AGENT_SHARED_TOKEN"] = ""
os.environ["ALLOW_INSECURE_NO_AGENT_TOKEN"] = "true"


@pytest.fixture(scope="session")
def server_root() -> Path:
    return ROOT


@pytest.fixture(scope="session")
def repo_root() -> Path:
    return REPO_ROOT


@pytest.fixture(scope="session")
def templates_dir() -> Path:
    return TEMPLATES_DIR


def bootstrap_test_app(monkeypatch, *, create_schema: bool = False):
    monkeypatch.setenv("DATABASE_URL", "sqlite+pysqlite:///:memory:")
    monkeypatch.setenv("BOOTSTRAP_USERNAME", TEST_BOOTSTRAP_USERNAME)
    monkeypatch.setenv("BOOTSTRAP_PASSWORD", TEST_BOOTSTRAP_PASSWORD)
    monkeypatch.setenv("UI_COOKIE_SECURE", "false")
    monkeypatch.setenv("ALLOW_INSECURE_NO_AGENT_TOKEN", "true")
    monkeypatch.setenv("AGENT_SHARED_TOKEN", "")
    monkeypatch.setenv("DB_AUTO_CREATE_TABLES", "true")
    monkeypatch.setenv("DB_REQUIRE_MIGRATIONS_UP_TO_DATE", "false")
    monkeypatch.setenv("MFA_REQUIRE_FOR_PRIVILEGED", "false")

    for name in list(sys.modules):
        if name == "app" or name.startswith("app."):
            sys.modules.pop(name, None)

    app_factory = importlib.import_module("app.app_factory")
    if create_schema:
        db_mod = importlib.import_module("app.db")
        importlib.import_module("app.models")
        db_mod.Base.metadata.create_all(bind=db_mod.engine)
    return app_factory.create_app()


def login_test_client(client, *, username: str = TEST_BOOTSTRAP_USERNAME, password: str = TEST_BOOTSTRAP_PASSWORD) -> dict[str, str]:
    response = client.post("/auth/login", json={"username": username, "password": password})
    assert response.status_code == 200, response.text
    csrf = client.cookies.get("fleet_csrf")
    return {"X-CSRF-Token": csrf} if csrf else {}


@pytest.fixture
def auth_client_factory():
    @contextmanager
    def _factory(app, *, username: str = TEST_BOOTSTRAP_USERNAME, password: str = TEST_BOOTSTRAP_PASSWORD):
        from fastapi.testclient import TestClient

        with TestClient(app) as client:
            headers = login_test_client(client, username=username, password=password)
            yield client, headers

    return _factory
