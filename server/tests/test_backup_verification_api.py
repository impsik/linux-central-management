import importlib
import sqlite3


def _boot_app(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "sqlite+pysqlite:///:memory:")
    monkeypatch.setenv("BOOTSTRAP_USERNAME", "admin")
    monkeypatch.setenv("BOOTSTRAP_PASSWORD", "admin-password-123")
    monkeypatch.setenv("UI_COOKIE_SECURE", "false")
    monkeypatch.setenv("ALLOW_INSECURE_NO_AGENT_TOKEN", "true")
    monkeypatch.setenv("AGENT_SHARED_TOKEN", "")
    monkeypatch.setenv("DB_AUTO_CREATE_TABLES", "true")
    monkeypatch.setenv("DB_REQUIRE_MIGRATIONS_UP_TO_DATE", "false")
    monkeypatch.setenv("MFA_REQUIRE_FOR_PRIVILEGED", "false")

    app_factory = importlib.import_module("app.app_factory")
    return app_factory.create_app()


def test_backup_verification_happy_path(monkeypatch, tmp_path):
    app = _boot_app(monkeypatch)

    db_path = tmp_path / "backup.sqlite"
    conn = sqlite3.connect(str(db_path))
    cur = conn.cursor()
    cur.execute("PRAGMA user_version=3;")
    cur.execute("CREATE TABLE sample(id INTEGER PRIMARY KEY, name TEXT);")
    cur.execute("INSERT INTO sample(name) VALUES('ok');")
    conn.commit()
    conn.close()

    from fastapi.testclient import TestClient

    with TestClient(app) as client:
        r = client.post("/auth/login", json={"username": "admin", "password": "admin-password-123"})
        assert r.status_code == 200, r.text

        run = client.post(
            "/backup-verification/runs",
            json={
                "backup_path": str(db_path),
                "expected_schema_version": 2,
            },
        )
        assert run.status_code == 200, run.text
        data = run.json()
        assert data["status"] == "verified"
        assert data["integrity_ok"] is True
        assert data["restore_ok"] is True
        assert data["compatibility_ok"] is True
        assert data["schema_version"] == 3

        latest = client.get("/backup-verification/latest")
        assert latest.status_code == 200, latest.text
        assert latest.json()["id"] == data["id"]


def test_backup_verification_schema_mismatch_fails(monkeypatch, tmp_path):
    app = _boot_app(monkeypatch)

    db_path = tmp_path / "backup-low-schema.sqlite"
    conn = sqlite3.connect(str(db_path))
    cur = conn.cursor()
    cur.execute("PRAGMA user_version=1;")
    cur.execute("CREATE TABLE sample(id INTEGER PRIMARY KEY, name TEXT);")
    conn.commit()
    conn.close()

    from fastapi.testclient import TestClient

    with TestClient(app) as client:
        r = client.post("/auth/login", json={"username": "admin", "password": "admin-password-123"})
        assert r.status_code == 200, r.text

        run = client.post(
            "/backup-verification/runs",
            json={
                "backup_path": str(db_path),
                "expected_schema_version": 2,
            },
        )
        assert run.status_code == 200, run.text
        data = run.json()
        assert data["status"] == "failed"
        assert data["integrity_ok"] is True
        assert data["restore_ok"] is True
        assert data["compatibility_ok"] is False
        assert data["schema_version"] == 1
