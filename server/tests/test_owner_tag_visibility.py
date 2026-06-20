from types import SimpleNamespace


def test_non_admin_host_visibility_requires_matching_owner_tag(monkeypatch):
    from app.services import user_scopes

    monkeypatch.setattr(user_scopes, 'get_user_scope_selectors', lambda db, user: [])

    user = SimpleNamespace(username='imre', role='operator', id='u1')
    owned_host = SimpleNamespace(labels={'owner': 'imre'})
    foreign_host = SimpleNamespace(labels={'owner': 'alice'})
    unlabeled_host = SimpleNamespace(labels={})

    assert user_scopes.is_host_visible_to_user(None, user, owned_host) is True
    assert user_scopes.is_host_visible_to_user(None, user, foreign_host) is False
    assert user_scopes.is_host_visible_to_user(None, user, unlabeled_host) is False


def test_non_admin_scope_selectors_grant_visibility(monkeypatch):
    from app.services import user_scopes

    monkeypatch.setattr(user_scopes, 'get_user_scope_selectors', lambda db, user: [{'env': ['prod']}])

    user = SimpleNamespace(username='imre', role='operator', id='u1')
    foreign_but_scoped = SimpleNamespace(labels={'owner': 'alice', 'env': 'prod'})
    owned_even_without_scope_match = SimpleNamespace(labels={'owner': 'imre', 'env': 'dev'})

    assert user_scopes.is_host_visible_to_user(None, user, foreign_but_scoped) is True
    assert user_scopes.is_host_visible_to_user(None, user, owned_even_without_scope_match) is True


def test_non_admin_team_scope_matches_comma_separated_host_team(monkeypatch):
    from app.services import user_scopes

    monkeypatch.setattr(user_scopes, 'get_user_scope_selectors', lambda db, user: [{'team': ['Linux']}])

    user = SimpleNamespace(username='gauss', role='operator', id='u1')
    linux_host = SimpleNamespace(labels={'team': 'Linux, Database'})
    database_only_host = SimpleNamespace(labels={'team': 'Database'})

    assert user_scopes.is_host_visible_to_user(None, user, linux_host) is True
    assert user_scopes.is_host_visible_to_user(None, user, database_only_host) is False
