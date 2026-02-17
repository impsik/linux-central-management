from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import get_db
from ..deps import require_ui_user
from ..models import Host, HostCVEStatus, HostPackage
from ..services.user_scopes import is_host_visible_to_user

router = APIRouter(prefix="/search", tags=["search"])


@router.get("/packages")
def search_packages(name: str, version: str | None = None, db: Session = Depends(get_db), user=Depends(require_ui_user)):
    stmt = (
        select(Host.hostname, Host.agent_id, HostPackage.version, HostPackage.arch)
        .join(HostPackage, Host.id == HostPackage.host_id)
        .where(HostPackage.name == name)
    )
    if version:
        if "*" in version or "?" in version:
            out = []
            for ch in version:
                if ch == "*":
                    out.append("%")
                elif ch == "?":
                    out.append("_")
                elif ch in ("%", "_", "\\"):
                    out.append("\\" + ch)
                else:
                    out.append(ch)
            like_pattern = "".join(out)
            stmt = stmt.where(HostPackage.version.like(like_pattern, escape="\\"))
        else:
            stmt = stmt.where(HostPackage.version == version)
    rows = db.execute(stmt).all()
    allowed = {
        h.agent_id
        for h in db.execute(select(Host)).scalars().all()
        if is_host_visible_to_user(db, user, h)
    }
    return [{"hostname": r[0], "agent_id": r[1], "version": r[2], "arch": r[3]} for r in rows if r[1] in allowed]


@router.get("/cve")
def search_cve(cve: str, affected: bool = True, db: Session = Depends(get_db), user=Depends(require_ui_user)):
    cve_norm = (cve or "").strip().upper()
    if not cve_norm.startswith("CVE-"):
        return []

    stmt = (
        select(Host.hostname, Host.agent_id, HostCVEStatus.affected, HostCVEStatus.checked_at)
        .join(HostCVEStatus, Host.id == HostCVEStatus.host_id)
        .where(HostCVEStatus.cve == cve_norm)
    )
    if affected:
        stmt = stmt.where(HostCVEStatus.affected == True)  # noqa: E712

    rows = db.execute(stmt).all()
    allowed = {
        h.agent_id
        for h in db.execute(select(Host)).scalars().all()
        if is_host_visible_to_user(db, user, h)
    }
    return [
        {"hostname": r[0], "agent_id": r[1], "affected": bool(r[2]), "checked_at": r[3]}
        for r in rows
        if r[1] in allowed
    ]
