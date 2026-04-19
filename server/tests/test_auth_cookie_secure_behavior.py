import importlib
from types import SimpleNamespace


def _make_request(scheme='http', xfp=None):
    headers = {}
    if xfp is not None:
        headers['x-forwarded-proto'] = xfp
    return SimpleNamespace(url=SimpleNamespace(scheme=scheme), headers=headers)


def test_explicit_ui_cookie_secure_false_overrides_https_autodetect(monkeypatch):
    auth = importlib.import_module('app.routers.auth')
    monkeypatch.setenv('UI_COOKIE_SECURE', 'false')

    req = _make_request(scheme='http', xfp='https')
    assert auth._cookie_secure_for(req) is False


def test_explicit_ui_cookie_secure_true_forces_secure_cookie(monkeypatch):
    auth = importlib.import_module('app.routers.auth')
    monkeypatch.setenv('UI_COOKIE_SECURE', 'true')

    req = _make_request(scheme='http')
    assert auth._cookie_secure_for(req) is True


def test_cookie_secure_autodetects_https_only_when_env_is_unset(monkeypatch):
    auth = importlib.import_module('app.routers.auth')
    monkeypatch.delenv('UI_COOKIE_SECURE', raising=False)

    assert auth._cookie_secure_for(_make_request(scheme='https')) is True
    assert auth._cookie_secure_for(_make_request(scheme='http', xfp='https')) is True
    assert auth._cookie_secure_for(_make_request(scheme='http')) is False
