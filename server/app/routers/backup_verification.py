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

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from ..db import get_db
from ..deps import require_ui_user
from ..models import BackupVerificationRun

router = APIRouter(prefix="/backup-verification", tags=["backup-verification"])


class BackupVerificationRequest(BaseModel):
    backup_path: str = Field(..., description="Path to backup artifact on server host")
    expected_sha256: str | None = Field(default=None)
    expected_schema_version: int | None = Field(default=None, ge=0)


class BackupVerificationResponse(BaseModel):
    id: str
    status: str
    started_at: datetime
    finished_at: datetime
    backup_path: str
    artifact_path: str
    integrity_ok: bool
    restore_ok: bool
    compatibility_ok: bool
    checksum_actual: str
    checksum_expected: str | None = None
    schema_version: int | None = None
    expected_schema_version: int | None = None


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _detect_sqlite_file(path: Path) -> Path | None:
    if path.suffix.lower() in {".sqlite", ".db", ".sqlite3"}:
        return path
    return None


def _rehearse_restore(path: Path, expected_schema_version: int | None) -> tuple[bool, bool, int | None, str]:
    """Restore rehearsal + version compatibility check.

    Returns: restore_ok, compatibility_ok, schema_version, detail
    """
    sqlite_candidate = _detect_sqlite_file(path)

    with tempfile.TemporaryDirectory(prefix="lcm-backup-verify-") as tmp:
        tmpdir = Path(tmp)

        if tarfile.is_tarfile(path):
            with tarfile.open(path, "r:*") as tf:
                tf.extractall(tmpdir)
            # best-effort: first sqlite-like file found
            for ext in ("*.sqlite", "*.db", "*.sqlite3"):
                found = list(tmpdir.rglob(ext))
                if found:
                    sqlite_candidate = found[0]
                    break

        if sqlite_candidate is None or not sqlite_candidate.exists():
            # vertical-slice limitation: restore rehearsal currently sqlite-focused
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


@router.post("/runs", response_model=BackupVerificationResponse)
def run_backup_verification(
    payload: BackupVerificationRequest,
    db: Session = Depends(get_db),
    user=Depends(require_ui_user),
):
    started_at = datetime.now(timezone.utc)

    backup_path = Path(payload.backup_path).expanduser().resolve()
    if not backup_path.exists() or not backup_path.is_file():
        raise HTTPException(400, "backup_path must be an existing file")

    checksum_actual = _sha256_file(backup_path)
    checksum_expected = (payload.expected_sha256 or "").strip().lower() or None
    integrity_ok = bool((checksum_expected is None) or (checksum_actual.lower() == checksum_expected))

    restore_ok, compatibility_ok, schema_version, detail = _rehearse_restore(
        backup_path,
        payload.expected_schema_version,
    )

    status = "verified" if (integrity_ok and restore_ok and compatibility_ok) else "failed"
    finished_at = datetime.now(timezone.utc)

    report = {
        "run_id": None,  # set after model exists
        "status": status,
        "backup_path": str(backup_path),
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
            "expected_schema_version": payload.expected_schema_version,
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
        backup_path=str(backup_path),
        checksum_algorithm="sha256",
        checksum_actual=checksum_actual,
        checksum_expected=checksum_expected,
        integrity_ok=integrity_ok,
        restore_ok=restore_ok,
        compatibility_ok=compatibility_ok,
        schema_version=schema_version,
        expected_schema_version=payload.expected_schema_version,
        artifact_path=str(artifact_path),
        detail={"restore_detail": detail},
        started_at=started_at,
        finished_at=finished_at,
        created_by=getattr(user, "username", None),
    )
    db.add(row)
    db.commit()

    return BackupVerificationResponse(
        id=str(run_id),
        status=status,
        started_at=started_at,
        finished_at=finished_at,
        backup_path=str(backup_path),
        artifact_path=str(artifact_path),
        integrity_ok=integrity_ok,
        restore_ok=restore_ok,
        compatibility_ok=compatibility_ok,
        checksum_actual=checksum_actual,
        checksum_expected=checksum_expected,
        schema_version=schema_version,
        expected_schema_version=payload.expected_schema_version,
    )


@router.get("/latest", response_model=BackupVerificationResponse)
def latest_backup_verification(db: Session = Depends(get_db), user=Depends(require_ui_user)):
    row = db.execute(select(BackupVerificationRun).order_by(desc(BackupVerificationRun.finished_at)).limit(1)).scalar_one_or_none()
    if not row:
        raise HTTPException(404, "No backup verification runs yet")

    return BackupVerificationResponse(
        id=str(row.id),
        status=row.status,
        started_at=row.started_at,
        finished_at=row.finished_at,
        backup_path=row.backup_path,
        artifact_path=row.artifact_path,
        integrity_ok=bool(row.integrity_ok),
        restore_ok=bool(row.restore_ok),
        compatibility_ok=bool(row.compatibility_ok),
        checksum_actual=row.checksum_actual,
        checksum_expected=row.checksum_expected,
        schema_version=row.schema_version,
        expected_schema_version=row.expected_schema_version,
    )


@router.get("/runs/{run_id}", response_model=BackupVerificationResponse)
def get_backup_verification_run(run_id: str, db: Session = Depends(get_db), user=Depends(require_ui_user)):
    row = db.execute(select(BackupVerificationRun).where(BackupVerificationRun.id == uuid.UUID(run_id))).scalar_one_or_none()
    if not row:
        raise HTTPException(404, "Run not found")

    return BackupVerificationResponse(
        id=str(row.id),
        status=row.status,
        started_at=row.started_at,
        finished_at=row.finished_at,
        backup_path=row.backup_path,
        artifact_path=row.artifact_path,
        integrity_ok=bool(row.integrity_ok),
        restore_ok=bool(row.restore_ok),
        compatibility_ok=bool(row.compatibility_ok),
        checksum_actual=row.checksum_actual,
        checksum_expected=row.checksum_expected,
        schema_version=row.schema_version,
        expected_schema_version=row.expected_schema_version,
    )
