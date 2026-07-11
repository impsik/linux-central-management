import importlib
import sys


def _create_app(monkeypatch, *, account_limit=10, ip_limit=30):
    monkeypatch.setenv("DATABASE_URL", "sqlite+pysqlite:///:memory:")
    monkeypatch.setenv("BOOTSTRAP_USERNAME", "admin")
    monkeypatch.setenv("BOOTSTRAP_PASSWORD", "admin-password-123")
    monkeypatch.setenv("UI_COOKIE_SECURE", "false")
    monkeypatch.setenv("ALLOW_INSECURE_NO_AGENT_TOKEN", "true")
    monkeypatch.setenv("AGENT_SHARED_TOKEN", "")
    monkeypatch.setenv("DB_AUTO_CREATE_TABLES", "true")
    monkeypatch.setenv("DB_REQUIRE_MIGRATIONS_UP_TO_DATE", "false")
    monkeypatch.setenv("MFA_REQUIRE_FOR_PRIVILEGED", "false")
    monkeypatch.setenv("LOGIN_RATE_LIMIT_PER_MINUTE", str(account_limit))
    monkeypatch.setenv("LOGIN_IP_RATE_LIMIT_PER_MINUTE", str(ip_limit))
    for name in list(sys.modules):
        if name == "app" or name.startswith("app."):
            sys.modules.pop(name, None)
    return importlib.import_module("app.app_factory").create_app()


def test_unknown_user_still_performs_password_verification(monkeypatch):
    from fastapi.testclient import TestClient

    app = _create_app(monkeypatch)
    auth = importlib.import_module("app.routers.auth")
    original_verify = auth.pwd_context.verify
    checked_hashes = []

    def recording_verify(password, password_hash):
        checked_hashes.append(password_hash)
        return original_verify(password, password_hash)

    monkeypatch.setattr(auth.pwd_context, "verify", recording_verify)
    with TestClient(app) as client:
        unknown = client.post(
            "/auth/login",
            json={"username": "definitely-unknown", "password": "wrong-password"},
        )
        known = client.post(
            "/auth/login",
            json={"username": "admin", "password": "wrong-password"},
        )

    assert unknown.status_code == known.status_code == 401
    assert unknown.json() == known.json() == {"detail": "Invalid username or password"}
    assert len(checked_hashes) == 2
    assert checked_hashes[0] == auth._DUMMY_PASSWORD_HASH
    assert checked_hashes[1] != auth._DUMMY_PASSWORD_HASH


def test_ip_limit_blocks_username_spraying(monkeypatch):
    from fastapi.testclient import TestClient

    app = _create_app(monkeypatch, account_limit=10, ip_limit=2)
    with TestClient(app) as client:
        first = client.post("/auth/login", json={"username": "guess-one", "password": "wrong"})
        second = client.post("/auth/login", json={"username": "guess-two", "password": "wrong"})
        blocked = client.post("/auth/login", json={"username": "guess-three", "password": "wrong"})

    assert first.status_code == second.status_code == 401
    assert blocked.status_code == 429
    assert blocked.json()["detail"].startswith("Too many login attempts.")
