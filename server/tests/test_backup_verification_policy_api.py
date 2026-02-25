import importlib
import sqlite3
from datetime import datetime, timedelta, timezone


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


def test_backup_verification_policy_run_now_and_notifications(monkeypatch, tmp_path):
    app = _boot_app(monkeypatch)

    db_path = tmp_path / "backup.sqlite"
    conn = sqlite3.connect(str(db_path))
    cur = conn.cursor()
    cur.execute("PRAGMA user_version=2;")
    cur.execute("CREATE TABLE sample(id INTEGER PRIMARY KEY, name TEXT);")
    conn.commit()
    conn.close()

    from fastapi.testclient import TestClient

    with TestClient(app) as client:
        r = client.post("/auth/login", json={"username": "admin", "password": "admin-password-123"})
        assert r.status_code == 200, r.text
        csrf = client.cookies.get("fleet_csrf")
        headers = {"X-CSRF-Token": csrf} if csrf else {}

        put = client.put(
            "/backup-verification/policy",
            json={
                "enabled": True,
                "backup_path": str(db_path),
                "expected_schema_version": 1,
                "schedule_kind": "daily",
                "timezone": "UTC",
                "time_hhmm": "03:00",
                "stale_after_hours": 1,
                "alert_on_failure": True,
                "alert_on_stale": True,
            },
            headers=headers,
        )
        assert put.status_code == 200, put.text

        run = client.post("/backup-verification/policy/run-now", headers=headers)
        assert run.status_code == 200, run.text
        d = run.json()
        assert d["status"] == "verified"

        # Force stale condition via DB and ensure dashboard notifications include backup verification alert.
        from app.db import SessionLocal
        from app.models import BackupVerificationPolicy, BackupVerificationRun

        with SessionLocal() as db:
            p = db.query(BackupVerificationPolicy).first()
            rr = db.query(BackupVerificationRun).order_by(BackupVerificationRun.finished_at.desc()).first()
            rr.finished_at = datetime.now(timezone.utc) - timedelta(hours=2)
            p.stale_after_hours = 1
            db.commit()

        n = client.get("/dashboard/notifications")
        assert n.status_code == 200, n.text
        items = n.json().get("items") or []
        kinds = {it.get("kind") for it in items}
        assert "backup_verification_stale" in kinds
