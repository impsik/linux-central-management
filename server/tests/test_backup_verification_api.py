import sqlite3

from conftest import bootstrap_test_app


def test_backup_verification_happy_path(monkeypatch, tmp_path, auth_client_factory):
    app = bootstrap_test_app(monkeypatch)

    db_path = tmp_path / "backup.sqlite"
    conn = sqlite3.connect(str(db_path))
    cur = conn.cursor()
    cur.execute("PRAGMA user_version=3;")
    cur.execute("CREATE TABLE sample(id INTEGER PRIMARY KEY, name TEXT);")
    cur.execute("INSERT INTO sample(name) VALUES('ok');")
    conn.commit()
    conn.close()

    with auth_client_factory(app) as (client, headers):
        run = client.post(
            "/backup-verification/runs",
            json={
                "backup_path": str(db_path),
                "expected_schema_version": 2,
            },
            headers=headers,
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


def test_backup_verification_schema_mismatch_fails(monkeypatch, tmp_path, auth_client_factory):
    app = bootstrap_test_app(monkeypatch)

    db_path = tmp_path / "backup-low-schema.sqlite"
    conn = sqlite3.connect(str(db_path))
    cur = conn.cursor()
    cur.execute("PRAGMA user_version=1;")
    cur.execute("CREATE TABLE sample(id INTEGER PRIMARY KEY, name TEXT);")
    conn.commit()
    conn.close()

    with auth_client_factory(app) as (client, headers):
        run = client.post(
            "/backup-verification/runs",
            json={
                "backup_path": str(db_path),
                "expected_schema_version": 2,
            },
            headers=headers,
        )
        assert run.status_code == 200, run.text
        data = run.json()
        assert data["status"] == "failed"
        assert data["integrity_ok"] is True
        assert data["restore_ok"] is True
        assert data["compatibility_ok"] is False
        assert data["schema_version"] == 1
