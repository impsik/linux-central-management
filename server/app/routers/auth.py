from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from passlib.context import CryptContext
from pydantic import BaseModel
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from ..config import settings
from ..db import get_db
from ..deps import CSRF_COOKIE, SESSION_COOKIE, get_current_session_from_request, require_admin_user, require_ui_user, sha256_hex
from ..models import AppSession, AppUser
from ..services.db_utils import transaction
from ..services.rbac import permissions_for

router = APIRouter(prefix="/auth", tags=["auth"])

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class LoginRequest(BaseModel):
    username: str
    password: str


class RegisterRequest(BaseModel):
    username: str
    password: str


class ResetPasswordRequest(BaseModel):
    username: str
    password: str


@router.post("/login")
def auth_login(payload: LoginRequest, request: Request, db: Session = Depends(get_db)):
    username = (payload.username or "").strip()
    password = payload.password or ""
    if not username or not password:
        raise HTTPException(400, "username and password are required")

    # Basic brute-force guard (single-process in-memory). Good enough for LAN MVP.
    from ..services.rate_limit import FixedWindowRateLimiter

    global _LOGIN_LIMITER  # noqa: PLW0603
    try:
        _LOGIN_LIMITER
    except NameError:
        _LOGIN_LIMITER = FixedWindowRateLimiter(limit=10, window_seconds=60)

    ip = (getattr(request.client, "host", None) or "unknown").strip()
    rl = _LOGIN_LIMITER.check(f"login:{ip}:{username.lower()}")
    _LOGIN_LIMITER.cleanup()
    if not rl.allowed:
        raise HTTPException(429, f"Too many login attempts. Try again in {rl.retry_after_seconds}s")

    user = db.execute(
        select(AppUser).where(AppUser.username == username, AppUser.is_active == True)  # noqa: E712
    ).scalar_one_or_none()
    if not user or not pwd_context.verify(password, user.password_hash):
        raise HTTPException(401, "Invalid username or password")

    token = secrets.token_urlsafe(32)
    token_hash = sha256_hex(token)
    now = datetime.now(timezone.utc)
    expires = now + timedelta(days=int(getattr(settings, "ui_session_days", 30)))

    # Cleanup expired sessions (best-effort)
    try:
        db.execute(delete(AppSession).where(AppSession.expires_at <= now))
    except Exception:
        pass

    # MFA gating: for admin/operator, require MFA enrollment and per-session verification.
    role = (getattr(user, "role", "operator") or "operator").lower()
    require_mfa = bool(getattr(settings, "mfa_require_for_privileged", True)) and role in ("admin", "operator")

    sess = AppSession(user_id=user.id, token_sha256=token_hash, expires_at=expires)
    if not require_mfa:
        sess.mfa_verified_at = now
    db.add(sess)
    db.commit()

    body: dict = {"ok": True, "username": user.username}
    if require_mfa:
        body["mfa_setup_required"] = not bool(getattr(user, "mfa_enabled", False))
        body["mfa_required"] = bool(getattr(user, "mfa_enabled", False))

    resp = JSONResponse(body)

    resp.set_cookie(
        key=SESSION_COOKIE,
        value=token,
        httponly=True,
        samesite="lax",
        secure=bool(getattr(settings, "ui_cookie_secure", False)),
        expires=int(expires.timestamp()),
        path="/",
    )

    # CSRF protection: double-submit cookie.
    # Frontend must echo this value in X-CSRF-Token for state-changing requests.
    csrf = secrets.token_urlsafe(32)
    resp.set_cookie(
        key=CSRF_COOKIE,
        value=csrf,
        httponly=False,
        samesite="lax",
        secure=bool(getattr(settings, "ui_cookie_secure", False)),
        expires=int(expires.timestamp()),
        path="/",
    )

    return resp


@router.get("/admin-info")
def auth_admin_info():
    return {"admin_username": getattr(settings, "bootstrap_username", "admin")}


@router.get("/admin/users")
def auth_admin_users(request: Request, db: Session = Depends(get_db)):
    require_admin_user(request, db)

    rows = db.execute(select(AppUser).order_by(AppUser.created_at.asc())).scalars().all()
    items = []
    for u in rows:
        items.append(
            {
                "id": str(u.id),
                "username": u.username,
                "role": (getattr(u, "role", "operator") or "operator"),
                "active": bool(getattr(u, "is_active", True)),
                "mfa_enabled": bool(getattr(u, "mfa_enabled", False)),
                "created_at": u.created_at.isoformat() if getattr(u, "created_at", None) else None,
            }
        )
    return {"items": items}


@router.post("/users/{username}/delete")
def delete_user(username: str, request: Request, db: Session = Depends(get_db), user: AppUser = Depends(require_ui_user)):
    """Deactivate an app user.

    Policy: allowed for admin and operator, but never for the bootstrap admin user.
    We deactivate (is_active=false) instead of deleting rows for safety/auditability.
    """

    perms = permissions_for(user)
    if not perms.get("can_delete_app_users"):
        raise HTTPException(403, "Insufficient permissions to delete users")

    uname = (username or "").strip()
    if not uname:
        raise HTTPException(400, "username required")

    # Protect bootstrap admin
    bootstrap = (getattr(settings, "bootstrap_username", None) or "admin").strip()
    if uname == bootstrap:
        raise HTTPException(400, "Cannot delete bootstrap admin user")

    # Prevent self-delete to avoid accidental lockout
    if uname == user.username:
        raise HTTPException(400, "Cannot delete your own user")

    target = db.execute(select(AppUser).where(AppUser.username == uname)).scalar_one_or_none()
    if not target:
        raise HTTPException(404, "user not found")

    with transaction(db):
        target.is_active = False
        # Revoke all sessions for that user
        db.execute(delete(AppSession).where(AppSession.user_id == target.id))

    return {"ok": True, "username": uname, "active": False}


@router.post("/register")
def auth_register(payload: RegisterRequest, request: Request, db: Session = Depends(get_db)):
    require_admin_user(request, db)
    username = (payload.username or "").strip()
    password = payload.password or ""
    if not username or not password:
        raise HTTPException(400, "username and password are required")
    if any(ch.isspace() for ch in username):
        raise HTTPException(400, "username must not contain whitespace")
    if len(password) < 8:
        raise HTTPException(400, "password must be at least 8 characters")

    existing = db.execute(select(AppUser).where(AppUser.username == username)).scalar_one_or_none()
    if existing:
        raise HTTPException(409, "username already exists")

    db.add(AppUser(username=username, password_hash=pwd_context.hash(password), is_active=True))
    db.commit()
    return {"ok": True, "username": username}


@router.post("/reset-password")
def auth_reset_password(payload: ResetPasswordRequest, request: Request, db: Session = Depends(get_db)):
    require_admin_user(request, db)
    username = (payload.username or "").strip()
    password = payload.password or ""
    if not username or not password:
        raise HTTPException(400, "username and password are required")
    if len(password) < 8:
        raise HTTPException(400, "password must be at least 8 characters")

    user = db.execute(select(AppUser).where(AppUser.username == username)).scalar_one_or_none()
    if not user:
        raise HTTPException(404, "user not found")

    user.password_hash = pwd_context.hash(password)
    db.commit()
    return {"ok": True, "username": username}


@router.post("/logout")
def auth_logout(request: Request, db: Session = Depends(get_db)):
    token = request.cookies.get(SESSION_COOKIE)
    if token:
        token_hash = sha256_hex(token)
        db.execute(delete(AppSession).where(AppSession.token_sha256 == token_hash))
        db.commit()
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(SESSION_COOKIE, path="/")
    return resp


@router.get("/me")
def auth_me(request: Request, db: Session = Depends(get_db), user: AppUser = Depends(require_ui_user)):
    perms = permissions_for(user)

    role = (perms.get("role") or "operator").lower()
    require_mfa = bool(getattr(settings, "mfa_require_for_privileged", True)) and role in ("admin", "operator")
    mfa_enabled = bool(getattr(user, "mfa_enabled", False))

    sess_res = get_current_session_from_request(request, db)
    mfa_verified = False
    if sess_res:
        sess, _u = sess_res
        mfa_verified = bool(getattr(sess, "mfa_verified_at", None))

    resp = JSONResponse(
        {
            "ok": True,
            "username": user.username,
            "role": role,
            "permissions": perms,
            "mfa": {
                "required": require_mfa,
                "enabled": mfa_enabled,
                "verified": mfa_verified,
                "setup_required": bool(require_mfa and not mfa_enabled),
                "verify_required": bool(require_mfa and mfa_enabled and not mfa_verified),
            },
        }
    )

    # Ensure CSRF cookie exists for older sessions / upgraded deployments.
    if not request.cookies.get(CSRF_COOKIE):
        csrf = secrets.token_urlsafe(32)
        resp.set_cookie(
            key=CSRF_COOKIE,
            value=csrf,
            httponly=False,
            samesite="lax",
            secure=bool(getattr(settings, "ui_cookie_secure", False)),
            path="/",
        )

    return resp
