from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from app.services.host_router_utils import apply_host_metadata_update, clean_optional_str, normalize_env_map


def test_clean_optional_str_trims_and_allows_blank():
    assert clean_optional_str(None, field="hostname") is None
    assert clean_optional_str("  host-01  ", field="hostname") == "host-01"
    assert clean_optional_str("   ", field="hostname") == ""


def test_clean_optional_str_rejects_overlong_values():
    with pytest.raises(HTTPException) as exc:
        clean_optional_str("x" * 256, field="hostname")
    assert exc.value.status_code == 400
    assert "hostname too long" in str(exc.value.detail)


def test_normalize_env_map_trims_and_drops_blank_keys():
    assert normalize_env_map(None) is None
    assert normalize_env_map({" FOO ": " bar ", "": "x", "   ": "y"}) == {"FOO": "bar"}


def test_normalize_env_map_rejects_overlong_key_and_value():
    with pytest.raises(HTTPException) as key_exc:
        normalize_env_map({"x" * 129: "ok"})
    assert key_exc.value.status_code == 400
    assert "env key too long" in str(key_exc.value.detail)

    with pytest.raises(HTTPException) as value_exc:
        normalize_env_map({"FOO": "x" * 2049})
    assert value_exc.value.status_code == 400
    assert "env value too long" in str(value_exc.value.detail)


def test_apply_host_metadata_update_updates_owner_env_vars_and_legacy_env():
    host = SimpleNamespace(hostname="old-host", labels={"team": "core", "env": "test", "env_vars": {"env": "test"}})

    labels = apply_host_metadata_update(
        host,
        hostname="new-host",
        role="web",
        owner="alice",
        env={"env": "prelive", "FOO": "bar"},
    )

    assert host.hostname == "new-host"
    assert labels["team"] == "core"
    assert labels["role"] == "web"
    assert labels["owner"] == "alice"
    assert labels["env_vars"] == {"env": "prelive", "FOO": "bar"}
    assert labels["env"] == "prelive"


def test_apply_host_metadata_update_removes_legacy_env_when_env_key_missing():
    host = SimpleNamespace(hostname="old-host", labels={"team": "ops", "env": "test", "env_vars": {"env": "test"}})

    labels = apply_host_metadata_update(
        host,
        hostname=None,
        role=None,
        owner=None,
        env={},
    )

    assert labels["env_vars"] == {}
    assert "env" not in labels
    assert host.labels == labels
