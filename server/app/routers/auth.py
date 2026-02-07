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
from ..deps import SESSION_COOKIE, require_admin_user, require_ui_user, sha256_hex
from ..models import AppSession, AppUser
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

    db.add(AppSession(user_id=user.id, token_sha256=token_hash, expires_at=expires))
    db.commit()

    resp = JSONResponse({"ok": True, "username": user.username})
    resp.set_cookie(
        key=SESSION_COOKIE,
        value=token,
        httponly=True,
        samesite="lax",
        secure=bool(getattr(settings, "ui_cookie_secure", False)),
        expires=int(expires.timestamp()),
        path="/",
    )
    return resp


@router.get("/admin-info")
def auth_admin_info():
    return {"admin_username": getattr(settings, "bootstrap_username", "admin")}


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
def auth_me(user: AppUser = Depends(require_ui_user)):
    perms = permissions_for(user)
    return {"ok": True, "username": user.username, "role": perms.get("role"), "permissions": perms}
