from __future__ import annotations

import hashlib
import json
import shutil
import sqlite3
import tarfile
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy.orm import Session

from ..models import BackupVerificationRun


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def detect_sqlite_file(path: Path) -> Path | None:
    if path.suffix.lower() in {".sqlite", ".db", ".sqlite3"}:
        return path
    return None


def rehearse_restore(path: Path, expected_schema_version: int | None) -> tuple[bool, bool, int | None, str]:
    """Restore rehearsal + version compatibility check.

    Returns: restore_ok, compatibility_ok, schema_version, detail
    """
    sqlite_candidate = detect_sqlite_file(path)

    with tempfile.TemporaryDirectory(prefix="lcm-backup-verify-") as tmp:
        tmpdir = Path(tmp)

        if tarfile.is_tarfile(path):
            with tarfile.open(path, "r:*") as tf:
                tf.extractall(tmpdir)
            for ext in ("*.sqlite", "*.db", "*.sqlite3"):
                found = list(tmpdir.rglob(ext))
                if found:
                    sqlite_candidate = found[0]
                    break

        if sqlite_candidate is None or not sqlite_candidate.exists():
            return True, True, None, "No sqlite payload found; extraction rehearsal succeeded"

        rehearse_copy = tmpdir / "rehearsal.sqlite"
        shutil.copy2(sqlite_candidate, rehearse_copy)

        conn = sqlite3.connect(str(rehearse_copy))
        try:
            cur = conn.cursor()
            row = cur.execute("PRAGMA integrity_check;").fetchone()
            if not row or str(row[0]).lower() != "ok":
                return False, False, None, f"SQLite integrity_check failed: {row}"
            schema_row = cur.execute("PRAGMA user_version;").fetchone()
            schema_version = int(schema_row[0] if schema_row else 0)
        finally:
            conn.close()

        compatibility_ok = True
        if expected_schema_version is not None and schema_version < expected_schema_version:
            compatibility_ok = False

        return True, compatibility_ok, schema_version, "SQLite restore rehearsal passed"


def run_and_persist_backup_verification(
    db: Session,
    *,
    backup_path: str,
    expected_sha256: str | None,
    expected_schema_version: int | None,
    created_by: str | None,
) -> BackupVerificationRun:
    started_at = datetime.now(timezone.utc)

    bpath = Path(backup_path).expanduser().resolve()
    checksum_actual = sha256_file(bpath)
    checksum_expected = (expected_sha256 or "").strip().lower() or None
    integrity_ok = bool((checksum_expected is None) or (checksum_actual.lower() == checksum_expected))

    restore_ok, compatibility_ok, schema_version, detail = rehearse_restore(
        bpath,
        expected_schema_version,
    )

    status = "verified" if (integrity_ok and restore_ok and compatibility_ok) else "failed"
    finished_at = datetime.now(timezone.utc)

    report = {
        "run_id": None,
        "status": status,
        "backup_path": str(bpath),
        "integrity": {
            "ok": integrity_ok,
            "algorithm": "sha256",
            "actual": checksum_actual,
            "expected": checksum_expected,
        },
        "restore_rehearsal": {
            "ok": restore_ok,
            "detail": detail,
        },
        "compatibility": {
            "ok": compatibility_ok,
            "schema_version": schema_version,
            "expected_schema_version": expected_schema_version,
        },
        "started_at": started_at.isoformat(),
        "finished_at": finished_at.isoformat(),
    }

    report_dir = Path("/tmp/lcm-backup-verification-reports")
    report_dir.mkdir(parents=True, exist_ok=True)
    run_id = uuid.uuid4()
    report["run_id"] = str(run_id)
    artifact_path = report_dir / f"{run_id}.json"
    artifact_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    row = BackupVerificationRun(
        id=run_id,
        status=status,
        backup_path=str(bpath),
        checksum_algorithm="sha256",
        checksum_actual=checksum_actual,
        checksum_expected=checksum_expected,
        integrity_ok=integrity_ok,
        restore_ok=restore_ok,
        compatibility_ok=compatibility_ok,
        schema_version=schema_version,
        expected_schema_version=expected_schema_version,
        artifact_path=str(artifact_path),
        detail={"restore_detail": detail},
        started_at=started_at,
        finished_at=finished_at,
        created_by=created_by,
    )
    db.add(row)
    db.flush()
    return row
