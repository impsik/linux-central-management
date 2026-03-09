from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from ..db import get_db
from ..deps import require_admin_user, require_ui_user
from ..models import BackupVerificationPolicy, BackupVerificationRun
from ..services.audit import log_event
from ..services.backup_verification import run_and_persist_backup_verification
from ..services.db_utils import transaction

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


class BackupVerificationPolicyPayload(BaseModel):
    enabled: bool = True
    backup_path: str
    expected_sha256: str | None = None
    expected_schema_version: int | None = Field(default=None, ge=0)
    schedule_kind: str = Field(default="daily")  # daily|weekly
    timezone: str = Field(default="UTC")
    time_hhmm: str = Field(default="03:00")
    weekday: int | None = Field(default=0, ge=0, le=6)
    stale_after_hours: int = Field(default=36, ge=1, le=24 * 30)
    alert_on_failure: bool = True
    alert_on_stale: bool = True


@router.post("/runs", response_model=BackupVerificationResponse)
def run_backup_verification(
    payload: BackupVerificationRequest,
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(require_ui_user),
):
    from pathlib import Path

    backup_path = Path(payload.backup_path).expanduser().resolve()
    if not backup_path.exists() or not backup_path.is_file():
        raise HTTPException(400, "backup_path must be an existing file")

    with transaction(db):
        row = run_and_persist_backup_verification(
            db,
            backup_path=str(backup_path),
            expected_sha256=payload.expected_sha256,
            expected_schema_version=payload.expected_schema_version,
            created_by=getattr(user, "username", None),
        )
        log_event(
            db,
            action="backup_verification.run",
            actor=user,
            request=request,
            target_type="backup_verification_run",
            target_id=str(row.id),
            meta={"status": row.status, "trigger": "manual"},
        )

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


@router.get("/policy")
def get_backup_verification_policy(db: Session = Depends(get_db), user=Depends(require_admin_user)):
    p = db.execute(select(BackupVerificationPolicy).order_by(BackupVerificationPolicy.created_at.asc()).limit(1)).scalar_one_or_none()
    if not p:
        return {"configured": False}
    return {
        "configured": True,
        "enabled": bool(p.enabled),
        "backup_path": p.backup_path,
        "expected_sha256": p.expected_sha256,
        "expected_schema_version": p.expected_schema_version,
        "schedule_kind": p.schedule_kind,
        "timezone": p.timezone,
        "time_hhmm": p.time_hhmm,
        "weekday": p.weekday,
        "stale_after_hours": p.stale_after_hours,
        "alert_on_failure": bool(p.alert_on_failure),
        "alert_on_stale": bool(p.alert_on_stale),
        "next_run_at": p.next_run_at.isoformat() if p.next_run_at else None,
        "last_run_at": p.last_run_at.isoformat() if p.last_run_at else None,
        "last_status": p.last_status,
        "last_error": p.last_error,
        "last_alert_at": p.last_alert_at.isoformat() if p.last_alert_at else None,
    }


@router.put("/policy")
def upsert_backup_verification_policy(
    payload: BackupVerificationPolicyPayload,
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(require_admin_user),
):
    now = datetime.now(timezone.utc)
    next_run = now + timedelta(minutes=1)
    with transaction(db):
        p = db.execute(select(BackupVerificationPolicy).order_by(BackupVerificationPolicy.created_at.asc()).limit(1)).scalar_one_or_none()
        if not p:
            p = BackupVerificationPolicy()
            db.add(p)
        p.enabled = bool(payload.enabled)
        p.backup_path = payload.backup_path
        p.expected_sha256 = (payload.expected_sha256 or "").strip().lower() or None
        p.expected_schema_version = payload.expected_schema_version
        p.schedule_kind = payload.schedule_kind
        p.timezone = payload.timezone
        p.time_hhmm = payload.time_hhmm
        p.weekday = payload.weekday
        p.stale_after_hours = payload.stale_after_hours
        p.alert_on_failure = bool(payload.alert_on_failure)
        p.alert_on_stale = bool(payload.alert_on_stale)
        p.next_run_at = next_run if p.enabled else None
        log_event(
            db,
            action="backup_verification.policy.updated",
            actor=user,
            request=request,
            target_type="backup_verification_policy",
            meta={"enabled": bool(payload.enabled), "schedule_kind": payload.schedule_kind},
        )
    return {"ok": True, "next_run_at": next_run.isoformat() if payload.enabled else None}


@router.post("/policy/run-now", response_model=BackupVerificationResponse)
def run_backup_verification_policy_now(
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(require_admin_user),
):
    p = db.execute(select(BackupVerificationPolicy).order_by(BackupVerificationPolicy.created_at.asc()).limit(1)).scalar_one_or_none()
    if not p or not p.backup_path:
        raise HTTPException(400, "Backup verification policy is not configured")

    from pathlib import Path

    bpath = Path(p.backup_path).expanduser().resolve()
    if not bpath.exists() or not bpath.is_file():
        raise HTTPException(400, "configured backup_path does not exist")

    with transaction(db):
        row = run_and_persist_backup_verification(
            db,
            backup_path=str(bpath),
            expected_sha256=p.expected_sha256,
            expected_schema_version=p.expected_schema_version,
            created_by=getattr(user, "username", None),
        )
        p.last_run_at = row.finished_at
        p.last_status = row.status
        p.last_error = None if row.status == "verified" else "verification failed"
        log_event(
            db,
            action="backup_verification.run",
            actor=user,
            request=request,
            target_type="backup_verification_run",
            target_id=str(row.id),
            meta={"status": row.status, "trigger": "policy_run_now"},
        )

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
