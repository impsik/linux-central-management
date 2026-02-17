from __future__ import annotations

import base64
import hashlib
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import get_db
from ..deps import require_admin_user, require_ui_user
from ..models import AppUser, Host, SSHKeyDeploymentRequest, UserSSHKey
from ..services.db_utils import transaction
from ..services.jobs import create_job_with_runs, push_job_to_agents
from ..services.user_scopes import filter_agent_ids_for_user

router = APIRouter(prefix="/sshkeys", tags=["sshkeys"])


def _fingerprint(pubkey: str) -> str:
    # Accept typical "ssh-ed25519 AAAA... comment" format.
    parts = (pubkey or "").strip().split()
    if len(parts) < 2:
        raise HTTPException(400, "invalid public key")

    key_type = parts[0].strip()
    # Security-first: only allow modern keys by default.
    if key_type not in ("ssh-ed25519", "ssh-rsa"):
        raise HTTPException(400, "unsupported key type (use ssh-ed25519 or ssh-rsa)")

    b64 = parts[1]
    try:
        raw = base64.b64decode(b64.encode("ascii"), validate=True)
    except Exception:
        raise HTTPException(400, "invalid public key")
    h = hashlib.sha256(raw).digest()
    fp = base64.b64encode(h).decode("ascii").rstrip("=")
    return f"SHA256:{fp}"


class SSHKeyAdd(BaseModel):
    name: str = Field(default="")
    public_key: str


@router.get("")
def list_my_keys(db: Session = Depends(get_db), user: AppUser = Depends(require_ui_user)):
    rows = (
        db.execute(
            select(UserSSHKey)
            .where(UserSSHKey.user_id == user.id, UserSSHKey.revoked_at.is_(None))
            .order_by(UserSSHKey.created_at.desc())
        )
        .scalars()
        .all()
    )
    return {
        "items": [
            {
                "id": str(k.id),
                "name": k.name,
                "fingerprint": k.fingerprint,
                "public_key": k.public_key,
                "created_at": k.created_at.isoformat() if k.created_at else None,
            }
            for k in rows
        ]
    }


@router.post("")
def add_key(payload: SSHKeyAdd, db: Session = Depends(get_db), user: AppUser = Depends(require_ui_user)):
    pub = (payload.public_key or "").strip()
    fp = _fingerprint(pub)

    with transaction(db):
        # prevent duplicates per user
        existing = db.execute(
            select(UserSSHKey).where(UserSSHKey.user_id == user.id, UserSSHKey.fingerprint == fp, UserSSHKey.revoked_at.is_(None))
        ).scalar_one_or_none()
        if existing:
            return {
                "id": str(existing.id),
                "fingerprint": existing.fingerprint,
                "created": False,
                "existing": True,
                "existing_name": existing.name,
            }

        k = UserSSHKey(user_id=user.id, name=(payload.name or "").strip(), public_key=pub, fingerprint=fp)
        db.add(k)

    return {"id": str(k.id), "fingerprint": fp, "created": True}


@router.delete("/{key_id}")
def revoke_key(key_id: str, db: Session = Depends(get_db), user: AppUser = Depends(require_ui_user)):
    k = db.execute(select(UserSSHKey).where(UserSSHKey.id == key_id, UserSSHKey.user_id == user.id)).scalar_one_or_none()
    if not k:
        raise HTTPException(404, "unknown key")

    now = datetime.now(timezone.utc)
    with transaction(db):
        k.revoked_at = now

        # If this key is revoked, any pending deployment requests for it can never be approved.
        # Mark them as failed so they don't linger in the admin queue.
        pending = (
            db.execute(
                select(SSHKeyDeploymentRequest).where(
                    SSHKeyDeploymentRequest.key_id == k.id,
                    SSHKeyDeploymentRequest.status == "pending",
                )
            )
            .scalars()
            .all()
        )
        for r in pending:
            r.status = "failed"
            r.error = "key revoked"
            r.finished_at = now

    return {"ok": True, "revoked": True}


class DeployRequestCreate(BaseModel):
    key_id: str
    agent_ids: list[str] = Field(default_factory=list)


@router.post("/deploy-requests")
def create_deploy_request(payload: DeployRequestCreate, db: Session = Depends(get_db), user: AppUser = Depends(require_ui_user)):
    scoped_agent_ids = filter_agent_ids_for_user(db, user, payload.agent_ids or [])
    if not scoped_agent_ids:
        raise HTTPException(400, "select at least one host within your scope")

    k = db.execute(select(UserSSHKey).where(UserSSHKey.id == payload.key_id, UserSSHKey.user_id == user.id, UserSSHKey.revoked_at.is_(None))).scalar_one_or_none()
    if not k:
        raise HTTPException(404, "unknown key")

    with transaction(db):
        req = SSHKeyDeploymentRequest(user_id=user.id, key_id=k.id, agent_ids=scoped_agent_ids, status="pending")
        db.add(req)

    return {"id": str(req.id), "status": req.status}


@router.get("/deploy-requests")
def list_my_deploy_requests(db: Session = Depends(get_db), user: AppUser = Depends(require_ui_user)):
    rows = (
        db.execute(
            select(SSHKeyDeploymentRequest)
            .where(SSHKeyDeploymentRequest.user_id == user.id)
            .order_by(SSHKeyDeploymentRequest.created_at.desc())
            .limit(200)
        )
        .scalars()
        .all()
    )
    return {
        "items": [
            {
                "id": str(r.id),
                "key_id": str(r.key_id),
                "agent_ids": r.agent_ids,
                "status": r.status,
                "created_at": r.created_at.isoformat() if r.created_at else None,
                "approved_by": r.approved_by,
                "error": r.error,
            }
            for r in rows
        ]
    }


@router.get("/admin/keys")
def admin_list_all_keys(db: Session = Depends(get_db), admin: AppUser = Depends(require_admin_user)):
    rows = (
        db.execute(
            select(UserSSHKey, AppUser.username)
            .join(AppUser, AppUser.id == UserSSHKey.user_id)
            .where(UserSSHKey.revoked_at.is_(None))
            .order_by(UserSSHKey.created_at.desc())
            .limit(500)
        )
        .all()
    )

    items = []
    for k, uname in rows:
        items.append(
            {
                "id": str(k.id),
                "user_id": str(k.user_id),
                "user_name": uname,
                "name": k.name,
                "fingerprint": k.fingerprint,
                "public_key": k.public_key,
                "created_at": k.created_at.isoformat() if k.created_at else None,
            }
        )

    return {"items": items}


@router.get("/admin/deploy-requests")
def admin_list_pending(db: Session = Depends(get_db), admin: AppUser = Depends(require_admin_user)):
    rows = (
        db.execute(
            select(SSHKeyDeploymentRequest)
            .where(SSHKeyDeploymentRequest.status == "pending")
            .order_by(SSHKeyDeploymentRequest.created_at.asc())
            .limit(200)
        )
        .scalars()
        .all()
    )

    user_ids = {r.user_id for r in rows if getattr(r, "user_id", None)}
    agent_ids: set[str] = set()
    for r in rows:
        for aid in (r.agent_ids or []):
            if aid:
                agent_ids.add(str(aid))

    user_map: dict[str, str] = {}
    if user_ids:
        for uid, uname in db.execute(select(AppUser.id, AppUser.username).where(AppUser.id.in_(user_ids))).all():
            user_map[str(uid)] = uname

    host_map: dict[str, str] = {}
    if agent_ids:
        for aid, hostname in db.execute(select(Host.agent_id, Host.hostname).where(Host.agent_id.in_(agent_ids))).all():
            host_map[str(aid)] = hostname

    key_ids = {r.key_id for r in rows if getattr(r, "key_id", None)}
    key_map: dict[str, dict[str, str]] = {}
    if key_ids:
        for kid, kname, kfp in db.execute(select(UserSSHKey.id, UserSSHKey.name, UserSSHKey.fingerprint).where(UserSSHKey.id.in_(key_ids))).all():
            key_map[str(kid)] = {"name": kname or "", "fingerprint": kfp or ""}

    items = []
    for r in rows:
        uid = str(r.user_id)
        kid = str(r.key_id)
        targets = []
        for aid in (r.agent_ids or []):
            if not aid:
                continue
            aid_s = str(aid)
            targets.append({"agent_id": aid_s, "hostname": host_map.get(aid_s) or aid_s})

        items.append(
            {
                "id": str(r.id),
                "user_id": uid,
                "user_name": user_map.get(uid) or uid,
                "key_id": kid,
                "key_name": (key_map.get(kid) or {}).get("name", ""),
                "key_fingerprint": (key_map.get(kid) or {}).get("fingerprint", ""),
                "agent_ids": r.agent_ids,
                "targets": targets,
                "status": r.status,
                "created_at": r.created_at.isoformat() if r.created_at else None,
            }
        )

    return {"items": items}


@router.post("/admin/deploy-requests/{req_id}/approve")
async def admin_approve(req_id: str, db: Session = Depends(get_db), admin: AppUser = Depends(require_admin_user)):
    r = db.execute(select(SSHKeyDeploymentRequest).where(SSHKeyDeploymentRequest.id == req_id)).scalar_one_or_none()
    if not r:
        raise HTTPException(404, "unknown request")
    if r.status != "pending":
        return {"id": str(r.id), "status": r.status}

    user = db.execute(select(AppUser).where(AppUser.id == r.user_id)).scalar_one_or_none()
    key = db.execute(select(UserSSHKey).where(UserSSHKey.id == r.key_id)).scalar_one_or_none()
    if not user or not key or key.revoked_at is not None:
        msg = "request refers to missing/revoked user/key"
        # Mark request as failed so it doesn't get stuck in the pending queue.
        with transaction(db):
            r.status = "failed"
            r.error = msg
            r.approved_by = getattr(admin, "username", None)
            r.approved_at = datetime.now(timezone.utc)
            r.finished_at = datetime.now(timezone.utc)
        return {"id": str(r.id), "status": "failed", "error": msg}

    agent_ids = [str(a) for a in (r.agent_ids or []) if a]
    if not agent_ids:
        msg = "no targets"
        with transaction(db):
            r.status = "failed"
            r.error = msg
            r.approved_by = getattr(admin, "username", None)
            r.approved_at = datetime.now(timezone.utc)
            r.finished_at = datetime.now(timezone.utc)
        return {"id": str(r.id), "status": "failed", "error": msg}

    with transaction(db):
        r.status = "approved"
        r.approved_by = getattr(admin, "username", None)
        r.approved_at = datetime.now(timezone.utc)

        linux_username = (getattr(key, "name", None) or "").strip() or user.username

        created = create_job_with_runs(
            db=db,
            job_type="ssh-key-deploy",
            payload={
                "username": linux_username,
                "public_key": key.public_key,
                "sudo_profile": "B",
            },
            agent_ids=agent_ids,
            created_by=getattr(admin, "username", None) or "admin",
            commit=False,
        )
        # store job key for traceability
        r.finished_at = None

    # IMPORTANT: agent Job struct expects service_name/action/package_name fields.
    await push_job_to_agents(
        agent_ids=agent_ids,
        job_payload_builder=lambda aid: {
            "job_id": created.job_key,
            "type": "ssh-key-deploy",
            "service_name": linux_username,  # linux username to create/update on target
            "action": "B",                  # sudo_profile
            "package_name": key.public_key,  # public_key
        },
    )

    return {"id": str(r.id), "status": "approved", "job_id": created.job_key}


@router.post("/admin/deploy-requests/{req_id}/reject")
def admin_reject(req_id: str, db: Session = Depends(get_db), admin: AppUser = Depends(require_admin_user)):
    r = db.execute(select(SSHKeyDeploymentRequest).where(SSHKeyDeploymentRequest.id == req_id)).scalar_one_or_none()
    if not r:
        raise HTTPException(404, "unknown request")
    if r.status != "pending":
        return {"id": str(r.id), "status": r.status}
    with transaction(db):
        r.status = "rejected"
        r.approved_by = getattr(admin, "username", None)
        r.approved_at = datetime.now(timezone.utc)
        r.finished_at = datetime.now(timezone.utc)
    return {"id": str(r.id), "status": "rejected"}
