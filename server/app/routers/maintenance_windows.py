from __future__ import annotations

from uuid import UUID
from zoneinfo import ZoneInfo

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import get_db
from ..deps import require_admin_user
from ..models import AppMaintenanceWindow
from ..services.audit import log_event

router = APIRouter(prefix="/maintenance-windows", tags=["maintenance-windows"])


class MaintenanceWindowPayload(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    timezone: str = Field(min_length=1, max_length=64)
    start_hhmm: str = Field(min_length=4, max_length=5)
    end_hhmm: str = Field(min_length=4, max_length=5)
    action_scope: list[str] = Field(default_factory=list)
    label_selector: dict = Field(default_factory=dict)
    enforcement_mode: str = Field(default="block")
    enabled: bool = True


def _normalize_hhmm(value: str, *, field_name: str) -> str:
    raw = str(value or "").strip()
    try:
        hh, mm = raw.split(":", 1)
        h = int(hh)
        m = int(mm)
    except Exception:
        raise HTTPException(400, f"{field_name} must be in HH:MM format")
    if h < 0 or h > 23 or m < 0 or m > 59:
        raise HTTPException(400, f"{field_name} must be a valid 24h time")
    return f"{h:02d}:{m:02d}"


def _validate_payload(payload: MaintenanceWindowPayload) -> dict:
    name = payload.name.strip()
    if not name:
        raise HTTPException(400, "name is required")

    timezone_name = str(payload.timezone or "").strip() or "UTC"
    try:
        ZoneInfo(timezone_name)
    except Exception:
        raise HTTPException(400, "timezone must be a valid IANA timezone")

    enforcement_mode = str(payload.enforcement_mode or "block").strip().lower()
    if enforcement_mode not in {"block", "warn"}:
        raise HTTPException(400, "enforcement_mode must be block or warn")

    action_scope = [str(x).strip().lower() for x in (payload.action_scope or []) if str(x).strip()]
    label_selector = payload.label_selector if isinstance(payload.label_selector, dict) else {}

    return {
        "name": name,
        "timezone": timezone_name,
        "start_hhmm": _normalize_hhmm(payload.start_hhmm, field_name="start_hhmm"),
        "end_hhmm": _normalize_hhmm(payload.end_hhmm, field_name="end_hhmm"),
        "action_scope": action_scope,
        "label_selector": label_selector,
        "enforcement_mode": enforcement_mode,
        "enabled": bool(payload.enabled),
    }


def _serialize(row: AppMaintenanceWindow) -> dict:
    return {
        "id": str(row.id),
        "name": row.name,
        "timezone": row.timezone,
        "start_hhmm": row.start_hhmm,
        "end_hhmm": row.end_hhmm,
        "action_scope": row.action_scope if isinstance(row.action_scope, list) else [],
        "label_selector": row.label_selector if isinstance(row.label_selector, dict) else {},
        "saved_view_id": str(row.saved_view_id) if row.saved_view_id else None,
        "enforcement_mode": row.enforcement_mode,
        "enabled": bool(row.enabled),
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "updated_at": row.updated_at.isoformat() if row.updated_at else None,
    }


@router.get("")
def list_maintenance_windows(db: Session = Depends(get_db), admin=Depends(require_admin_user)):
    rows = db.execute(select(AppMaintenanceWindow).order_by(AppMaintenanceWindow.created_at.asc())).scalars().all()
    return {"items": [_serialize(r) for r in rows]}


@router.post("")
def create_maintenance_window(payload: MaintenanceWindowPayload, request: Request, db: Session = Depends(get_db), admin=Depends(require_admin_user)):
    data = _validate_payload(payload)
    row = AppMaintenanceWindow(**data)
    db.add(row)
    db.commit()
    db.refresh(row)
    log_event(db, action="maintenance_window.create", actor=admin, request=request, target_type="maintenance_window", target_id=str(row.id), target_name=row.name)
    db.commit()
    return _serialize(row)


@router.put("/{window_id}")
def update_maintenance_window(window_id: UUID, payload: MaintenanceWindowPayload, request: Request, db: Session = Depends(get_db), admin=Depends(require_admin_user)):
    row = db.execute(select(AppMaintenanceWindow).where(AppMaintenanceWindow.id == window_id)).scalar_one_or_none()
    if not row:
        raise HTTPException(404, "Maintenance window not found")

    data = _validate_payload(payload)
    for key, value in data.items():
        setattr(row, key, value)
    db.commit()
    db.refresh(row)
    log_event(db, action="maintenance_window.update", actor=admin, request=request, target_type="maintenance_window", target_id=str(row.id), target_name=row.name)
    db.commit()
    return _serialize(row)


@router.delete("/{window_id}")
def delete_maintenance_window(window_id: UUID, request: Request, db: Session = Depends(get_db), admin=Depends(require_admin_user)):
    row = db.execute(select(AppMaintenanceWindow).where(AppMaintenanceWindow.id == window_id)).scalar_one_or_none()
    if not row:
        raise HTTPException(404, "Maintenance window not found")
    name = row.name
    wid = str(row.id)
    db.delete(row)
    db.commit()
    log_event(db, action="maintenance_window.delete", actor=admin, request=request, target_type="maintenance_window", target_id=wid, target_name=name)
    db.commit()
    return {"ok": True}
