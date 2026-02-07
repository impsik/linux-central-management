from __future__ import annotations

import subprocess

from fastapi import APIRouter, Depends, HTTPException

from ..deps import require_admin_user
from ..models import AppUser

router = APIRouter(prefix="/admin", tags=["admin"])


@router.post("/migrations/upgrade")
def migrations_upgrade(user: AppUser = Depends(require_admin_user)):
    """Run `alembic upgrade head` inside the container.

    This is an MVP convenience endpoint. In production, run migrations as part of deployment.
    """

    try:
        res = subprocess.run(["alembic", "upgrade", "head"], capture_output=True, text=True, timeout=60)
    except FileNotFoundError:
        raise HTTPException(500, "alembic not installed")
    except subprocess.TimeoutExpired:
        raise HTTPException(504, "migration timed out")

    if res.returncode != 0:
        raise HTTPException(500, f"migration failed: {res.stderr or res.stdout}")

    return {"ok": True, "stdout": res.stdout}
