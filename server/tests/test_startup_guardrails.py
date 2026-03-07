import importlib
import sys

import pytest


def _reload_app_modules():
    for k in list(sys.modules.keys()):
        if k == "app" or k.startswith("app."):
            sys.modules.pop(k, None)


def test_startup_blocks_non_local_insecure_defaults(monkeypatch):
    # Non-local signal: secure mode (no insecure bypass) and non-local DB host.
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://fleet:fleet@db:5432/fleet")
    monkeypatch.setenv("ALLOW_INSECURE_NO_AGENT_TOKEN", "false")
    monkeypatch.setenv("AGENT_SHARED_TOKEN", "change-me-agent-token")
    monkeypatch.setenv("BOOTSTRAP_PASSWORD", "change-me-long-random")
    monkeypatch.setenv("UI_COOKIE_SECURE", "false")
    monkeypatch.setenv("DB_AUTO_CREATE_TABLES", "true")
    monkeypatch.setenv("MFA_REQUIRE_FOR_PRIVILEGED", "true")
    monkeypatch.setenv("MFA_ENCRYPTION_KEY", "")

    _reload_app_modules()
    app_factory = importlib.import_module("app.app_factory")

    with pytest.raises(RuntimeError, match="Startup blocked by production guardrails"):
        app_factory._startup()


def test_startup_allows_local_dev_profile(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "sqlite+pysqlite:///:memory:")
    monkeypatch.setenv("ALLOW_INSECURE_NO_AGENT_TOKEN", "true")
    monkeypatch.setenv("AGENT_SHARED_TOKEN", "")
    monkeypatch.setenv("BOOTSTRAP_PASSWORD", "")
    monkeypatch.setenv("UI_COOKIE_SECURE", "false")
    monkeypatch.setenv("DB_AUTO_CREATE_TABLES", "true")
    monkeypatch.setenv("MFA_REQUIRE_FOR_PRIVILEGED", "false")
    monkeypatch.setenv("DB_REQUIRE_MIGRATIONS_UP_TO_DATE", "false")

    _reload_app_modules()
    app_factory = importlib.import_module("app.app_factory")

    # Should not raise guardrail errors in local dev mode.
    app_factory._startup()
