from __future__ import annotations

import hashlib
from datetime import datetime, timezone

from fastapi import Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import settings
from .db import get_db
from .models import AppSession, AppUser

SESSION_COOKIE = "fleet_session"
CSRF_COOKIE = "fleet_csrf"


def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def get_current_session_from_request(request: Request, db: Session) -> tuple[AppSession, AppUser] | None:
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        return None
    token_hash = sha256_hex(token)
    now = datetime.now(timezone.utc)
    sess = db.execute(
        select(AppSession).where(AppSession.token_sha256 == token_hash, AppSession.expires_at > now)
    ).scalar_one_or_none()
    if not sess:
        return None
    user = db.execute(
        select(AppUser).where(AppUser.id == sess.user_id, AppUser.is_active == True)  # noqa: E712
    ).scalar_one_or_none()
    if not user:
        return None
    return sess, user


def get_current_user_from_request(request: Request, db: Session) -> AppUser | None:
    res = get_current_session_from_request(request, db)
    if not res:
        return None
    _, user = res
    return user


def require_ui_user(request: Request, db: Session = Depends(get_db)) -> AppUser:
    user = get_current_user_from_request(request, db)
    if not user:
        raise HTTPException(401, "Not authenticated")
    return user


def require_admin_user(request: Request, db: Session = Depends(get_db)) -> AppUser:
    user = require_ui_user(request, db)

    # Backward compat: bootstrap_username is considered admin.
    admin_username = (getattr(settings, "bootstrap_username", None) or "").strip()
    if admin_username and user.username == admin_username:
        return user

    # New RBAC path
    try:
        from .services.rbac import require_admin

        return require_admin(user)
    except HTTPException:
        raise
    except Exception:
        # Fail closed
        raise HTTPException(403, "Admin privileges required")
