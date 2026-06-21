import importlib
from pathlib import Path

import pytest


def test_explicit_insecure_dev_mode_treats_compose_db_host_as_local(monkeypatch):
    config_mod = importlib.import_module("app.config")
    app_factory = importlib.import_module("app.app_factory")

    monkeypatch.setattr(config_mod.settings, "allow_insecure_no_agent_token", True)
    monkeypatch.setattr(config_mod.settings, "database_url", "postgresql+psycopg://fleet:fleet@db:5432/fleet")

    assert app_factory._is_non_local_deployment() is False


def test_non_local_when_insecure_override_is_disabled(monkeypatch):
    config_mod = importlib.import_module("app.config")
    app_factory = importlib.import_module("app.app_factory")

    monkeypatch.setattr(config_mod.settings, "allow_insecure_no_agent_token", False)
    monkeypatch.setattr(config_mod.settings, "database_url", "postgresql+psycopg://fleet:fleet@db:5432/fleet")

    assert app_factory._is_non_local_deployment() is True


def test_insecure_no_agent_token_startup_requires_loopback_bind(monkeypatch):
    config_mod = importlib.import_module("app.config")
    app_factory = importlib.import_module("app.app_factory")

    monkeypatch.setattr(config_mod.settings, "agent_shared_token", "")
    monkeypatch.setattr(config_mod.settings, "allow_insecure_no_agent_token", True)
    monkeypatch.setattr(config_mod.settings, "server_bind_host", "0.0.0.0")

    with pytest.raises(RuntimeError, match="SERVER_BIND_HOST='0.0.0.0' is not loopback"):
        app_factory._startup()


def test_insecure_no_agent_token_startup_allows_loopback_bind(monkeypatch):
    config_mod = importlib.import_module("app.config")
    app_factory = importlib.import_module("app.app_factory")

    monkeypatch.setattr(config_mod.settings, "agent_shared_token", "")
    monkeypatch.setattr(config_mod.settings, "allow_insecure_no_agent_token", True)
    monkeypatch.setattr(config_mod.settings, "server_bind_host", "127.0.0.1")
    monkeypatch.setattr(config_mod.settings, "auth_oidc_enabled", False)
    monkeypatch.setattr(config_mod.settings, "db_auto_create_tables", False)
    monkeypatch.setattr(config_mod.settings, "db_require_migrations_up_to_date", False)
    monkeypatch.setattr(config_mod.settings, "ui_revoke_all_sessions_on_startup", False)
    monkeypatch.setattr(config_mod.settings, "bootstrap_password", None)

    app_factory._startup()


def test_docker_compose_defaults_require_agent_token():
    root = Path(__file__).resolve().parents[2]
    for rel_path in ("deploy/docker/docker-compose.yml", "deploy/docker/env.example"):
        content = (root / rel_path).read_text(encoding="utf-8")
        assert "ALLOW_INSECURE_NO_AGENT_TOKEN" in content
        assert "ALLOW_INSECURE_NO_AGENT_TOKEN:-false" in content or "ALLOW_INSECURE_NO_AGENT_TOKEN=false" in content


def test_docker_compose_defaults_bind_server_to_network_interface():
    root = Path(__file__).resolve().parents[2]
    compose = (root / "deploy/docker/docker-compose.yml").read_text(encoding="utf-8")
    dockerfile = (root / "server/Dockerfile").read_text(encoding="utf-8")

    assert "SERVER_BIND_HOST: ${SERVER_BIND_HOST:-0.0.0.0}" in compose
    assert "--host ${SERVER_BIND_HOST:-0.0.0.0}" in dockerfile
