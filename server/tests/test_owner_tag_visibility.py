from types import SimpleNamespace


def test_non_admin_without_explicit_scopes_only_sees_matching_owner_tag(monkeypatch):
    from app.services import user_scopes

    monkeypatch.setattr(user_scopes, 'get_user_scope_selectors', lambda db, user: [])

    user = SimpleNamespace(username='imre', role='operator', id='u1')
    owned_host = SimpleNamespace(labels={'owner': 'imre'})
    foreign_host = SimpleNamespace(labels={'owner': 'alice'})
    unlabeled_host = SimpleNamespace(labels={})

    assert user_scopes.is_host_visible_to_user(None, user, owned_host) is True
    assert user_scopes.is_host_visible_to_user(None, user, foreign_host) is False
    assert user_scopes.is_host_visible_to_user(None, user, unlabeled_host) is False
