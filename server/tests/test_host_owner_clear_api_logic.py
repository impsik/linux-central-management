from types import SimpleNamespace


def test_update_host_metadata_clears_owner_when_owner_field_is_present_and_empty(monkeypatch):
    from app.routers import hosts as hosts_router
    from app.schemas import HostMetadataUpdate

    host = SimpleNamespace(agent_id='agent-1', hostname='srv-1', labels={'owner': 'imre', 'team': 'ops'})

    class _Result:
        def __init__(self, host_obj):
            self._host = host_obj

        def scalar_one_or_none(self):
            return self._host

    class _DB:
        def __init__(self, host_obj):
            self._host = host_obj
            self.committed = False

        def execute(self, _query):
            return _Result(self._host)

        def commit(self):
            self.committed = True

    monkeypatch.setattr(hosts_router, 'permissions_for', lambda user: {'can_manage_users': True})
    monkeypatch.setattr(hosts_router, 'is_host_visible_to_user', lambda db, user, host_obj: True)

    payload = HostMetadataUpdate(owner='')
    db = _DB(host)
    user = SimpleNamespace(username='admin')

    out = hosts_router.update_host_metadata('agent-1', payload, db=db, user=user)

    assert db.committed is True
    assert 'owner' not in host.labels
    assert host.labels['team'] == 'ops'
    assert 'owner' not in out['host']['labels']


def test_update_host_metadata_sets_owner_when_non_empty_owner_is_provided(monkeypatch):
    from app.routers import hosts as hosts_router
    from app.schemas import HostMetadataUpdate

    host = SimpleNamespace(agent_id='agent-1', hostname='srv-1', labels={'team': 'ops'})

    class _Result:
        def __init__(self, host_obj):
            self._host = host_obj

        def scalar_one_or_none(self):
            return self._host

    class _DB:
        def __init__(self, host_obj):
            self._host = host_obj
            self.committed = False

        def execute(self, _query):
            return _Result(self._host)

        def commit(self):
            self.committed = True

    monkeypatch.setattr(hosts_router, 'permissions_for', lambda user: {'can_manage_users': True})
    monkeypatch.setattr(hosts_router, 'is_host_visible_to_user', lambda db, user, host_obj: True)

    payload = HostMetadataUpdate(owner='alice')
    db = _DB(host)
    user = SimpleNamespace(username='admin')

    out = hosts_router.update_host_metadata('agent-1', payload, db=db, user=user)

    assert db.committed is True
    assert host.labels['owner'] == 'alice'
    assert out['host']['labels']['owner'] == 'alice'
