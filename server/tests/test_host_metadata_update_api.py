import importlib

from conftest import bootstrap_test_app


def _seed_host(agent_id="agent-1", hostname="old-host", labels=None):
    db_mod = importlib.import_module("app.db")
    models = importlib.import_module("app.models")
    labels = labels if labels is not None else {"team": "core"}
    with db_mod.SessionLocal() as db:
        db.add(models.Host(agent_id=agent_id, hostname=hostname, labels=labels))
        db.commit()


def test_update_host_metadata_name_role_env_and_preserve_existing(monkeypatch, auth_client_factory):
    app = bootstrap_test_app(monkeypatch, create_schema=True)
    _seed_host(labels={"team": "core", "role": "old"})

    with auth_client_factory(app) as (client, headers):
        resp = client.patch(
            "/hosts/agent-1/metadata",
            json={
                "hostname": "new-host",
                "role": "web",
                "env": {"FOO": "bar", "X": "1"},
            },
            headers=headers,
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["ok"] is True
        assert body["host"]["hostname"] == "new-host"
        assert body["host"]["labels"]["role"] == "web"
        assert body["host"]["labels"]["team"] == "core"
        assert body["host"]["labels"]["env_vars"] == {"FOO": "bar", "X": "1"}


def test_update_host_metadata_role_when_missing_and_env_replace_idempotent(monkeypatch, auth_client_factory):
    app = bootstrap_test_app(monkeypatch, create_schema=True)
    _seed_host(agent_id="agent-2", labels={"team": "ops", "env_vars": {"FOO": "old", "UNCHANGED": "yes"}})

    with auth_client_factory(app) as (client, headers):
        payload = {"role": "db", "env": {"FOO": "new", "BAR": "2"}}
        first = client.patch("/hosts/agent-2/metadata", json=payload, headers=headers)
        assert first.status_code == 200, first.text
        second = client.patch("/hosts/agent-2/metadata", json=payload, headers=headers)
        assert second.status_code == 200, second.text

        labels = second.json()["host"]["labels"]
        assert labels["role"] == "db"
        assert labels["team"] == "ops"
        assert labels["env_vars"] == {"FOO": "new", "BAR": "2"}


def test_update_host_metadata_env_key_sets_legacy_env_and_clears_on_remove(monkeypatch, auth_client_factory):
    app = bootstrap_test_app(monkeypatch, create_schema=True)
    _seed_host(agent_id="agent-3", labels={"team": "ops", "env_vars": {"env": "test"}, "env": "test"})

    with auth_client_factory(app) as (client, headers):

        set_resp = client.patch("/hosts/agent-3/metadata", json={"env": {"env": "prelive"}}, headers=headers)
        assert set_resp.status_code == 200, set_resp.text
        set_labels = set_resp.json()["host"]["labels"]
        assert set_labels["env_vars"] == {"env": "prelive"}
        assert set_labels["env"] == "prelive"

        clear_resp = client.patch("/hosts/agent-3/metadata", json={"env": {}}, headers=headers)
        assert clear_resp.status_code == 200, clear_resp.text
        clear_labels = clear_resp.json()["host"]["labels"]
        assert clear_labels["env_vars"] == {}
        assert "env" not in clear_labels
