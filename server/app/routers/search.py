from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import Host, HostPackage

router = APIRouter(prefix="/search", tags=["search"])


@router.get("/packages")
def search_packages(name: str, version: str | None = None, db: Session = Depends(get_db)):
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
    return [{"hostname": r[0], "agent_id": r[1], "version": r[2], "arch": r[3]} for r in rows]
