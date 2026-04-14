import importlib


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
