from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode

import httpx

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from passlib.context import CryptContext
from pydantic import BaseModel
from sqlalchemy import delete, func, or_, select
from sqlalchemy.orm import Session

from ..config import settings
from ..db import get_db
from ..deps import CSRF_COOKIE, SESSION_COOKIE, get_current_session_from_request, get_current_user_from_request, require_admin_user, require_ui_user, sha256_hex
from ..models import AppSavedView, AppSession, AppUser, AppUserScope
from ..services.user_scopes import get_user_scope_selectors, user_has_scope_limits
from ..services.audit import log_event
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


class SaveViewRequest(BaseModel):
    scope: str = "hosts"
    name: str
    payload: dict = {}
    is_shared: bool = False
    is_default_startup: bool = False


class DeleteViewRequest(BaseModel):
    scope: str = "hosts"
    name: str
    owner_username: str | None = None


class UserScopeSetRequest(BaseModel):
    selectors: list[dict] = []


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
    # Audit: successful login (no secrets)
    log_event(db, action="auth.login", actor=user, request=request)
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
    return {
        "admin_username": getattr(settings, "bootstrap_username", "admin"),
        "oidc_enabled": bool(getattr(settings, "auth_oidc_enabled", False)),
    }


def _oidc_discovery() -> dict:
    issuer = (getattr(settings, "auth_oidc_issuer", None) or "").strip().rstrip("/")
    if not issuer:
        raise HTTPException(500, "OIDC issuer is not configured")
    url = f"{issuer}/.well-known/openid-configuration"
    try:
        resp = httpx.get(url, timeout=8.0)
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        raise HTTPException(502, f"OIDC discovery failed: {e}")
    if not isinstance(data, dict) or not data.get("authorization_endpoint"):
        raise HTTPException(502, "OIDC discovery document is invalid")
    return data


@router.get("/oidc/login")
def auth_oidc_login():
    if not bool(getattr(settings, "auth_oidc_enabled", False)):
        raise HTTPException(404, "OIDC is disabled")

    disc = _oidc_discovery()
    authz = str(disc.get("authorization_endpoint") or "").strip()
    if not authz:
        raise HTTPException(502, "OIDC authorization endpoint not found")

    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    scopes = str(getattr(settings, "auth_oidc_scopes", "openid profile email") or "openid profile email").strip()

    query = urlencode(
        {
            "client_id": str(getattr(settings, "auth_oidc_client_id", "") or ""),
            "response_type": "code",
            "redirect_uri": str(getattr(settings, "auth_oidc_redirect_uri", "") or ""),
            "scope": scopes,
            "state": state,
            "nonce": nonce,
        }
    )

    # Redirect to IdP authorization endpoint and keep short-lived anti-CSRF cookies.
    from fastapi.responses import RedirectResponse

    redirect = RedirectResponse(url=f"{authz}?{query}", status_code=302)
    for c_name, c_val in (("fleet_oidc_state", state), ("fleet_oidc_nonce", nonce)):
        redirect.set_cookie(
            key=c_name,
            value=c_val,
            httponly=True,
            samesite="lax",
            secure=bool(getattr(settings, "ui_cookie_secure", False)),
            max_age=600,
            path="/",
        )
    return redirect


@router.get("/oidc/callback")
def auth_oidc_callback():
    raise HTTPException(501, "OIDC callback not implemented yet (next slice)")


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

    # Guardrail: never allow deactivating the last active admin.
    role_norm = (getattr(target, "role", "operator") or "operator").lower()
    if role_norm == "admin" and bool(getattr(target, "is_active", True)):
        active_admins = int(
            db.execute(
                select(func.count())
                .select_from(AppUser)
                .where(AppUser.is_active == True, AppUser.role == "admin")  # noqa: E712
            ).scalar_one()
            or 0
        )
        if active_admins <= 1:
            raise HTTPException(400, "Cannot deactivate the last active admin")

    with transaction(db):
        target.is_active = False
        # Revoke all sessions for that user
        db.execute(delete(AppSession).where(AppSession.user_id == target.id))
        log_event(db, action="user.deactivate", actor=user, request=request, target_type="app_user", target_name=uname)

    return {"ok": True, "username": uname, "active": False}


@router.post("/users/{username}/activate")
def activate_user(username: str, request: Request, db: Session = Depends(get_db), user: AppUser = Depends(require_ui_user)):
    perms = permissions_for(user)
    if not perms.get("can_delete_app_users"):
        raise HTTPException(403, "Insufficient permissions to activate users")

    uname = (username or "").strip()
    if not uname:
        raise HTTPException(400, "username required")

    target = db.execute(select(AppUser).where(AppUser.username == uname)).scalar_one_or_none()
    if not target:
        raise HTTPException(404, "user not found")

    with transaction(db):
        target.is_active = True
        log_event(db, action="user.activate", actor=user, request=request, target_type="app_user", target_name=uname)

    return {"ok": True, "username": uname, "active": True}


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

    u = AppUser(username=username, password_hash=pwd_context.hash(password), is_active=True)
    db.add(u)
    # Audit
    admin = require_ui_user(request, db)
    log_event(db, action="user.create", actor=admin, request=request, target_type="app_user", target_name=username)
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
    # Audit
    admin = require_ui_user(request, db)
    log_event(db, action="user.reset_password", actor=admin, request=request, target_type="app_user", target_name=username)
    db.commit()
    return {"ok": True, "username": username}


@router.post("/logout")
def auth_logout(request: Request, db: Session = Depends(get_db)):
    token = request.cookies.get(SESSION_COOKIE)
    if token:
        token_hash = sha256_hex(token)
        # Audit best-effort (actor might be unknown if session already gone)
        try:
            u = get_current_user_from_request(request, db)
        except Exception:
            u = None
        db.execute(delete(AppSession).where(AppSession.token_sha256 == token_hash))
        if u:
            log_event(db, action="auth.logout", actor=u, request=request)
        db.commit()
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(SESSION_COOKIE, path="/")
    return resp


@router.get("/views")
def auth_list_views(scope: str = "hosts", db: Session = Depends(get_db), user: AppUser = Depends(require_ui_user)):
    scope_norm = (scope or "hosts").strip().lower()
    rows = db.execute(
        select(AppSavedView, AppUser.username)
        .join(AppUser, AppUser.id == AppSavedView.user_id)
        .where(
            AppSavedView.scope == scope_norm,
            or_(AppSavedView.user_id == user.id, AppSavedView.is_shared == True),  # noqa: E712
        )
        .order_by(AppSavedView.is_shared.asc(), AppSavedView.name.asc())
    ).all()

    items = []
    for r, owner_username in rows:
        can_edit = str(getattr(r, "user_id", "")) == str(user.id)
        items.append(
            {
                "scope": scope_norm,
                "name": r.name,
                "payload": r.payload if isinstance(r.payload, dict) else {},
                "is_shared": bool(getattr(r, "is_shared", False)),
                "is_default_startup": bool(getattr(r, "is_default_startup", False) and can_edit),
                "owner_username": owner_username,
                "can_edit": can_edit,
                "updated_at": r.updated_at.isoformat() if getattr(r, "updated_at", None) else None,
            }
        )

    return {"items": items}


@router.post("/views")
def auth_save_view(payload: SaveViewRequest, db: Session = Depends(get_db), user: AppUser = Depends(require_ui_user)):
    scope_norm = (payload.scope or "hosts").strip().lower()
    name = (payload.name or "").strip()
    if not name:
        raise HTTPException(400, "view name is required")

    perms = permissions_for(user)
    is_shared = bool(getattr(payload, "is_shared", False))
    is_default_startup = bool(getattr(payload, "is_default_startup", False))
    if is_shared and (perms.get("role") != "admin"):
        raise HTTPException(403, "Only admin can create shared views")

    existing = db.execute(
        select(AppSavedView).where(
            AppSavedView.user_id == user.id,
            AppSavedView.scope == scope_norm,
            AppSavedView.name == name,
        )
    ).scalar_one_or_none()

    if is_default_startup:
        old_defaults = db.execute(
            select(AppSavedView).where(AppSavedView.user_id == user.id, AppSavedView.scope == scope_norm)
        ).scalars().all()
        for row in old_defaults:
            row.is_default_startup = False

    if existing:
        existing.payload = payload.payload or {}
        existing.is_shared = is_shared
        existing.is_default_startup = is_default_startup
    else:
        db.add(
            AppSavedView(
                user_id=user.id,
                scope=scope_norm,
                name=name,
                payload=payload.payload or {},
                is_shared=is_shared,
                is_default_startup=is_default_startup,
            )
        )

    db.commit()
    return {"ok": True, "scope": scope_norm, "name": name}


@router.delete("/views")
def auth_delete_view(payload: DeleteViewRequest, db: Session = Depends(get_db), user: AppUser = Depends(require_ui_user)):
    scope_norm = (payload.scope or "hosts").strip().lower()
    name = (payload.name or "").strip()
    if not name:
        raise HTTPException(400, "view name is required")

    q = (
        select(AppSavedView, AppUser.username)
        .join(AppUser, AppUser.id == AppSavedView.user_id)
        .where(
            AppSavedView.scope == scope_norm,
            AppSavedView.name == name,
            or_(AppSavedView.user_id == user.id, AppSavedView.is_shared == True),  # noqa: E712
        )
    )
    owner_username_req = (payload.owner_username or "").strip()
    if owner_username_req:
        q = q.where(AppUser.username == owner_username_req)

    row_with_owner = db.execute(q).first()
    row = row_with_owner[0] if row_with_owner else None
    if not row:
        raise HTTPException(404, "view not found")

    owner = str(getattr(row, "user_id", "")) == str(user.id)
    perms = permissions_for(user)
    if not owner and not (bool(getattr(row, "is_shared", False)) and perms.get("role") == "admin"):
        raise HTTPException(403, "Not allowed to delete this view")

    db.execute(delete(AppSavedView).where(AppSavedView.id == row.id))
    db.commit()
    return {"ok": True, "scope": scope_norm, "name": name}


@router.get("/admin/users/{username}/scopes")
def auth_admin_get_user_scopes(username: str, request: Request, db: Session = Depends(get_db)):
    require_admin_user(request, db)

    target = db.execute(select(AppUser).where(AppUser.username == username)).scalar_one_or_none()
    if not target:
        raise HTTPException(404, "user not found")

    rows = db.execute(
        select(AppUserScope)
        .where(AppUserScope.user_id == target.id, AppUserScope.scope_type == "label_selector")
        .order_by(AppUserScope.created_at.asc())
    ).scalars().all()

    return {
        "username": target.username,
        "selectors": [r.selector if isinstance(r.selector, dict) else {} for r in rows],
    }


@router.post("/admin/users/{username}/scopes")
def auth_admin_set_user_scopes(
    username: str,
    payload: UserScopeSetRequest,
    request: Request,
    db: Session = Depends(get_db),
    admin: AppUser = Depends(require_admin_user),
):
    target = db.execute(select(AppUser).where(AppUser.username == username)).scalar_one_or_none()
    if not target:
        raise HTTPException(404, "user not found")

    selectors = payload.selectors or []
    norm: list[dict] = []
    for s in selectors:
        if isinstance(s, dict):
            norm.append(s)

    with transaction(db):
        db.execute(delete(AppUserScope).where(AppUserScope.user_id == target.id, AppUserScope.scope_type == "label_selector"))
        for sel in norm:
            db.add(AppUserScope(user_id=target.id, scope_type="label_selector", selector=sel))

        log_event(
            db,
            action="user.scope.update",
            actor=admin,
            request=request,
            target_type="app_user",
            target_name=target.username,
            meta={"selector_count": len(norm)},
        )

    return {"ok": True, "username": target.username, "selector_count": len(norm)}


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
            "scope": {
                "limited": user_has_scope_limits(db, user),
                "selectors": get_user_scope_selectors(db, user),
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
