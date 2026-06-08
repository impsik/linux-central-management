from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import get_db
from ..deps import require_ui_user
from ..models import Host, HostCVEStatus, HostPackage, CVEPackage
from ..services.user_scopes import filter_agent_ids_for_user
from ..services.deb_version import is_vulnerable
from ..services.rpm_version import is_vulnerable as is_rpm_vulnerable
from ..services.rbac import is_admin

router = APIRouter(prefix="/search", tags=["search"])


def release_key_for_host(os_id: str | None, os_version: str | None) -> str | None:
    os_id_norm = (os_id or "").strip().lower()
    os_ver = (os_version or "").strip().lower()
    if "20.04" in os_ver or "focal" in os_ver:
        return "focal"
    if "22.04" in os_ver or "jammy" in os_ver:
        return "jammy"
    if "24.04" in os_ver or "noble" in os_ver:
        return "noble"
    if os_id_norm in {"rhel", "redhat", "rocky", "almalinux", "centos", "fedora", "ol", "oracle"}:
        version = os_ver.split(".", 1)[0].strip()
        if version:
            return f"{os_id_norm}-{version}"
        return os_id_norm
    return None


@router.get("/packages")
def search_packages(name: str, version: str | None = None, db: Session = Depends(get_db), user=Depends(require_ui_user)):
    stmt = (
        select(Host.hostname, Host.agent_id, HostPackage.version, HostPackage.arch, Host.os_id, Host.os_version, HostPackage.manager)
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

    allowed = None
    if not is_admin(user):
        matched_agent_ids = [r[1] for r in rows]
        allowed = set(filter_agent_ids_for_user(db, user, matched_agent_ids))

    results = []
    for r in rows:
        if allowed is not None and r[1] not in allowed:
            continue
            
        cves = []
        release_key = release_key_for_host(r[4], r[5])

        if release_key and release_key in cve_map:
            for cve_id, fixed_ver in cve_map[release_key]:
                vulnerable = is_rpm_vulnerable(r[2], fixed_ver) if (r[6] or "").lower() == "rpm" else is_vulnerable(r[2], fixed_ver)
                if vulnerable:
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
    allowed = None
    if not is_admin(user):
        matched_agent_ids = [r[1] for r in rows]
        allowed = set(filter_agent_ids_for_user(db, user, matched_agent_ids))
    return [
        {"hostname": r[0], "agent_id": r[1], "affected": bool(r[2]), "checked_at": r[3]}
        for r in rows
        if allowed is None or r[1] in allowed
    ]
