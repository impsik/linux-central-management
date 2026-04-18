from types import SimpleNamespace

import pytest
from fastapi import HTTPException


class _ScalarResult:
    def __init__(self, value):
        self._value = value

    def scalar_one_or_none(self):
        return self._value


class _HostLookupDB:
    def __init__(self, host_obj, owner_user=None):
        self._host = host_obj
        self._owner_user = owner_user
        self.committed = False
        self._calls = 0

    def execute(self, _query):
        self._calls += 1
        if self._calls == 1:
            return _ScalarResult(self._host)
        return _ScalarResult(self._owner_user)

    def commit(self):
        self.committed = True


def test_update_host_metadata_clears_owner_when_owner_field_is_present_and_empty(monkeypatch):
    from app.routers import hosts as hosts_router
    from app.schemas import HostMetadataUpdate

    host = SimpleNamespace(agent_id='agent-1', hostname='srv-1', labels={'owner': 'imre', 'team': 'ops'})
    db = _HostLookupDB(host)
    user = SimpleNamespace(username='admin')

    monkeypatch.setattr(hosts_router, 'permissions_for', lambda user: {'can_manage_users': True})
    monkeypatch.setattr(hosts_router, 'is_host_visible_to_user', lambda db, user, host_obj: True)

    payload = HostMetadataUpdate(owner='')
    out = hosts_router.update_host_metadata('agent-1', payload, db=db, user=user)

    assert db.committed is True
    assert 'owner' not in host.labels
    assert host.labels['team'] == 'ops'
    assert 'owner' not in out['host']['labels']


def test_update_host_metadata_sets_owner_when_existing_user_is_provided(monkeypatch):
    from app.routers import hosts as hosts_router
    from app.schemas import HostMetadataUpdate

    host = SimpleNamespace(agent_id='agent-1', hostname='srv-1', labels={'team': 'ops'})
    db = _HostLookupDB(host, owner_user=SimpleNamespace(username='alice', is_active=True))
    user = SimpleNamespace(username='admin')

    monkeypatch.setattr(hosts_router, 'permissions_for', lambda user: {'can_manage_users': True})
    monkeypatch.setattr(hosts_router, 'is_host_visible_to_user', lambda db, user, host_obj: True)

    payload = HostMetadataUpdate(owner='alice')
    out = hosts_router.update_host_metadata('agent-1', payload, db=db, user=user)

    assert db.committed is True
    assert host.labels['owner'] == 'alice'
    assert out['host']['labels']['owner'] == 'alice'


def test_update_host_metadata_rejects_nonexistent_owner(monkeypatch):
    from app.routers import hosts as hosts_router
    from app.schemas import HostMetadataUpdate

    host = SimpleNamespace(agent_id='agent-1', hostname='srv-1', labels={'team': 'ops'})
    db = _HostLookupDB(host, owner_user=None)
    user = SimpleNamespace(username='admin')

    monkeypatch.setattr(hosts_router, 'permissions_for', lambda user: {'can_manage_users': True})
    monkeypatch.setattr(hosts_router, 'is_host_visible_to_user', lambda db, user, host_obj: True)

    payload = HostMetadataUpdate(owner='ghost-user')

    with pytest.raises(HTTPException) as exc:
        hosts_router.update_host_metadata('agent-1', payload, db=db, user=user)

    assert exc.value.status_code == 400
    assert "does not exist" in str(exc.value.detail)
    assert db.committed is False
    assert 'owner' not in host.labels
