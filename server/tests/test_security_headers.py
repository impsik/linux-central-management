import importlib
import sys

from fastapi.testclient import TestClient


def _reload_app_modules():
    for name in list(sys.modules.keys()):
        if name == "app" or name.startswith("app."):
            sys.modules.pop(name, None)


def _boot_app(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "sqlite+pysqlite:///:memory:")
    monkeypatch.setenv("SERVER_BIND_HOST", "127.0.0.1")
    monkeypatch.setenv("BOOTSTRAP_USERNAME", "admin")
    monkeypatch.setenv("BOOTSTRAP_PASSWORD", "admin-password-123")
    monkeypatch.setenv("UI_COOKIE_SECURE", "false")
    monkeypatch.setenv("ALLOW_INSECURE_NO_AGENT_TOKEN", "true")
    monkeypatch.setenv("AGENT_SHARED_TOKEN", "")
    monkeypatch.setenv("DB_AUTO_CREATE_TABLES", "true")
    monkeypatch.setenv("DB_REQUIRE_MIGRATIONS_UP_TO_DATE", "false")
    monkeypatch.setenv("MFA_REQUIRE_FOR_PRIVILEGED", "false")
    _reload_app_modules()
    app_factory = importlib.import_module("app.app_factory")
    return app_factory.create_app()


def test_default_csp_blocks_script_attrs_and_framing():
    app_factory = importlib.import_module("app.app_factory")
    csp = app_factory._default_content_security_policy("test-nonce")

    assert "script-src 'self' 'nonce-test-nonce'" in csp
    assert "script-src-attr 'none'" in csp
    assert "form-action 'self'" in csp
    assert "frame-src 'none'" in csp
    assert "manifest-src 'self'" in csp
    assert "worker-src 'none'" in csp
    assert "object-src 'none'" in csp
    assert "base-uri 'self'" in csp
    assert "frame-ancestors 'none'" in csp


def test_ui_response_gets_hardened_default_csp(monkeypatch):
    app = _boot_app(monkeypatch)

    with TestClient(app) as client:
        response = client.get("/login")

    assert response.status_code == 200
    csp = response.headers.get("Content-Security-Policy", "")
    assert "script-src 'self' 'nonce-" in csp
    assert "script-src-attr 'none'" in csp
    assert "form-action 'self'" in csp
    assert "frame-src 'none'" in csp
    assert "worker-src 'none'" in csp
