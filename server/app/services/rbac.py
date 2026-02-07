from __future__ import annotations

from fastapi import HTTPException

from ..models import AppUser


def is_admin(user: AppUser) -> bool:
    return (getattr(user, "role", "") or "").lower() == "admin"


def require_admin(user: AppUser) -> AppUser:
    if not is_admin(user):
        raise HTTPException(403, "Admin privileges required")
    return user


def permissions_for(user: AppUser) -> dict:
    role = (getattr(user, "role", "operator") or "operator").lower()

    # Start simple: explicit booleans, easy for frontend to consume
    perms = {
        "role": role,
        "can_view": True,
        "can_run_ansible": role in ("admin", "operator"),
        "can_manage_users": role == "admin",
        "can_manage_packages": role in ("admin", "operator"),
        "can_remove_packages": role == "admin",
        "can_manage_services": role in ("admin", "operator"),
        "can_lock_users": role == "admin",
        "can_use_terminal": role == "admin",
    }
    return perms
