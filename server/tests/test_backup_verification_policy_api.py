import sqlite3
from datetime import datetime, timedelta, timezone

from conftest import bootstrap_test_app


def test_backup_verification_policy_run_now_and_notifications(monkeypatch, tmp_path, auth_client_factory):
    app = bootstrap_test_app(monkeypatch)

    db_path = tmp_path / "backup.sqlite"
    conn = sqlite3.connect(str(db_path))
    cur = conn.cursor()
    cur.execute("PRAGMA user_version=2;")
    cur.execute("CREATE TABLE sample(id INTEGER PRIMARY KEY, name TEXT);")
    conn.commit()
    conn.close()

    with auth_client_factory(app) as (client, headers):
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
