from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..config import settings
from ..db import get_db
from ..deps import get_current_session_from_request, require_admin_user, require_ui_user
from ..models import AppSession, AppUser
from ..services.db_utils import transaction
from ..services.mfa import (
    decrypt_secret,
    encrypt_secret,
    generate_recovery_codes,
    hash_recovery_codes,
    now_utc,
    otpauth_uri,
    recovery_code_matches,
    verify_totp,
    new_totp_secret,
)

router = APIRouter(prefix="/auth/mfa", tags=["mfa"])


class CodePayload(BaseModel):
    code: str


@router.post("/enroll/start")
def enroll_start(request: Request, db: Session = Depends(get_db), user: AppUser = Depends(require_ui_user)):
    # Require encryption key if MFA is enabled.
    if not getattr(settings, "mfa_encryption_key", None):
        raise HTTPException(500, "MFA_ENCRYPTION_KEY not configured")

    secret = new_totp_secret()
    enc = encrypt_secret(secret)

    with transaction(db):
        user.totp_secret_pending_enc = enc
        user.mfa_pending_at = now_utc()

    uri = otpauth_uri(user.username, secret)

    # Optional QR helper (best-effort). Frontend can fall back to showing the URI.
    qr_data_url = None
    try:
        import base64
        from io import BytesIO

        import qrcode

        img = qrcode.make(uri)
        buf = BytesIO()
        img.save(buf, format="PNG")
        qr_data_url = "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode("ascii")
    except Exception:
        qr_data_url = None

    return {"ok": True, "otpauth_uri": uri, "qr_data_url": qr_data_url}


@router.post("/enroll/confirm")
def enroll_confirm(payload: CodePayload, db: Session = Depends(get_db), user: AppUser = Depends(require_ui_user)):
    if not getattr(user, "totp_secret_pending_enc", None):
        raise HTTPException(400, "No pending MFA enrollment")

    secret = decrypt_secret(user.totp_secret_pending_enc)
    if not verify_totp(secret, payload.code):
        raise HTTPException(400, "Invalid code")

    recovery_plain = generate_recovery_codes(10)
    recovery_hashes = hash_recovery_codes(recovery_plain)

    with transaction(db):
        user.totp_secret_enc = user.totp_secret_pending_enc
        user.totp_secret_pending_enc = None
        user.mfa_enabled = True
        user.mfa_enrolled_at = now_utc()
        user.mfa_pending_at = None
        user.recovery_codes = recovery_hashes

    return {"ok": True, "recovery_codes": recovery_plain}


@router.post("/verify")
def verify(payload: CodePayload, request: Request, db: Session = Depends(get_db)):
    res = get_current_session_from_request(request, db)
    if not res:
        raise HTTPException(401, "Not authenticated")
    sess, user = res

    role = (getattr(user, "role", "operator") or "operator").lower()
    require_mfa = bool(getattr(settings, "mfa_require_for_privileged", True)) and role in ("admin", "operator")
    if not require_mfa:
        # Nothing to do.
        return {"ok": True, "verified": True}

    if not getattr(user, "mfa_enabled", False) or not getattr(user, "totp_secret_enc", None):
        raise HTTPException(403, "MFA enrollment required")

    secret = decrypt_secret(user.totp_secret_enc)
    code = (payload.code or "").strip()

    ok = verify_totp(secret, code)
    used_recovery = False
    if not ok:
        # Try recovery codes
        if recovery_code_matches(user.recovery_codes or [], code):
            used_recovery = True
            ok = True

    if not ok:
        raise HTTPException(400, "Invalid code")

    with transaction(db):
        # If recovery code used, consume it.
        if used_recovery:
            from ..services.mfa import sha256_hex

            h = sha256_hex(code)
            user.recovery_codes = [x for x in (user.recovery_codes or []) if x != h]
        sess.mfa_verified_at = now_utc()

    return {"ok": True, "verified": True, "used_recovery": used_recovery}


class AdminResetPayload(BaseModel):
    username: str


@router.post("/admin/reset")
def admin_reset(payload: AdminResetPayload, request: Request, db: Session = Depends(get_db)):
    require_admin_user(request, db)
    uname = (payload.username or "").strip()
    if not uname:
        raise HTTPException(400, "username required")

    from sqlalchemy import select

    u = db.execute(select(AppUser).where(AppUser.username == uname)).scalar_one_or_none()
    if not u:
        raise HTTPException(404, "user not found")

    with transaction(db):
        u.mfa_enabled = False
        u.totp_secret_enc = None
        u.totp_secret_pending_enc = None
        u.mfa_enrolled_at = None
        u.mfa_pending_at = None
        u.recovery_codes = []

    return {"ok": True, "username": uname, "mfa_enabled": False}
