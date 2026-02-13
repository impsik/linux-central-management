from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from fastapi import Request
from sqlalchemy.orm import Session

from ..models import AppUser, AuditEvent


def _now() -> datetime:
    return datetime.now(timezone.utc)


def client_ip(request: Request | None) -> str | None:
    if not request:
        return None
    # Mirror get_client_ip() behavior but without importing agent services.
    xff = request.headers.get("X-Forwarded-For")
    if xff:
        return xff.split(",")[0].strip()
    xri = request.headers.get("X-Real-IP")
    if xri:
        return xri.strip()
    try:
        return request.client.host if request.client else None
    except Exception:
        return None


def user_agent(request: Request | None) -> str | None:
    if not request:
        return None
    ua = request.headers.get("User-Agent")
    return (ua[:500] if ua else None)


def truncate(s: Any, max_len: int = 500) -> str:
    t = "" if s is None else str(s)
    if len(t) > max_len:
        return t[: max_len - 3] + "..."
    return t


def log_event(
    db: Session,
    *,
    action: str,
    actor: AppUser | None,
    request: Request | None = None,
    target_type: str | None = None,
    target_id: str | None = None,
    target_name: str | None = None,
    meta: dict[str, Any] | None = None,
) -> None:
    """Best-effort audit log.

    Must never raise (audit logging must not break the primary action).
    """

    try:
        ev = AuditEvent(
            action=(action or "").strip()[:120],
            actor_user_id=getattr(actor, "id", None) if actor else None,
            actor_username=getattr(actor, "username", None) if actor else None,
            actor_role=getattr(actor, "role", None) if actor else None,
            ip_address=client_ip(request),
            user_agent=user_agent(request),
            target_type=(target_type or "")[:80] if target_type else None,
            target_id=(target_id or "")[:120] if target_id else None,
            target_name=(target_name or "")[:200] if target_name else None,
            meta=(meta or {}),
            created_at=_now(),
        )
        db.add(ev)
        # Don't commit here; caller's transaction context decides.
    except Exception:
        return
