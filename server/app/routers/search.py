from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import get_db
from ..deps import require_ui_user
from ..models import Host, HostCVEStatus, HostPackage, CVEPackage
from ..services.user_scopes import is_host_visible_to_user
from ..services.deb_version import is_vulnerable

router = APIRouter(prefix="/search", tags=["search"])


@router.get("/packages")
def search_packages(name: str, version: str | None = None, db: Session = Depends(get_db), user=Depends(require_ui_user)):
    stmt = (
        select(Host.hostname, Host.agent_id, HostPackage.version, HostPackage.arch, Host.os_version)
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
    
    # Pre-fetch CVE definitions for this package
    cve_defs = db.execute(select(CVEPackage).where(CVEPackage.package_name == name)).scalars().all()
    cve_map = {} # release -> [(cve_id, fixed_version)]
    for c in cve_defs:
        if c.release not in cve_map:
            cve_map[c.release] = []
        cve_map[c.release].append((c.cve_id, c.fixed_version))

    allowed = {
        h.agent_id
        for h in db.execute(select(Host)).scalars().all()
        if is_host_visible_to_user(db, user, h)
    }
    
    results = []
    for r in rows:
        # r = (hostname, agent_id, version, arch, os_version)
        if r[1] not in allowed:
            continue
            
        cves = []
        os_ver = (r[4] or "").lower()
        codename = None
        if "20.04" in os_ver or "focal" in os_ver: codename = "focal"
        elif "22.04" in os_ver or "jammy" in os_ver: codename = "jammy"
        elif "24.04" in os_ver or "noble" in os_ver: codename = "noble"
        
        if codename and codename in cve_map:
            for cve_id, fixed_ver in cve_map[codename]:
                if is_vulnerable(r[2], fixed_ver):
                    cves.append(cve_id)
        
        results.append({
            "hostname": r[0], 
            "agent_id": r[1], 
            "version": r[2], 
            "arch": r[3],
            "cves": cves
        })
        
    return results


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
