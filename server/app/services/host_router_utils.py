from __future__ import annotations

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import Host
from .rbac import is_admin, permissions_for
from .user_scopes import is_host_visible_to_user


def clean_optional_str(value: str | None, *, field: str, max_len: int = 255) -> str | None:
    if value is None:
        return None
    out = str(value).strip()
    if not out:
        return ""
    if len(out) > max_len:
        raise HTTPException(400, f"{field} too long (max {max_len})")
    return out


def require_permission(user, permission_key: str, message: str) -> None:
    perms = permissions_for(user)
    if not perms.get(permission_key):
        raise HTTPException(403, message)


def host_owned_by_user(user, host: Host | None) -> bool:
    if user is None or host is None:
        return False
    if is_admin(user):
        return True
    labels = (getattr(host, 'labels', None) or {}) if host is not None else {}
    owner = str(labels.get('owner', '') or '').strip()
    username = str(getattr(user, 'username', '') or '').strip()
    return bool(owner and username and owner == username)


def require_host_control_permission(user, host: Host, permission_key: str, message: str) -> None:
    if host_owned_by_user(user, host):
        return
    require_permission(user, permission_key, message)


def get_visible_host_or_404(db: Session, user, agent_id: str) -> Host:
    host = db.execute(select(Host).where(Host.agent_id == agent_id)).scalar_one_or_none()
    if not host or not is_host_visible_to_user(db, user, host):
        raise HTTPException(404, "Host not found")
    return host


def normalize_env_map(env: dict | None) -> dict[str, str] | None:
    if env is None:
        return None

    next_env: dict[str, str] = {}
    for k, v in (env or {}).items():
        kk = str(k or "").strip()
        vv = str(v or "").strip()
        if not kk:
            continue
        if len(kk) > 128:
            raise HTTPException(400, "env key too long (max 128)")
        if len(vv) > 2048:
            raise HTTPException(400, f"env value too long for key '{kk}' (max 2048)")
        next_env[kk] = vv
    return next_env


def apply_host_metadata_update(host: Host, *, hostname: str | None, role: str | None, owner: str | None, env: dict[str, str] | None) -> dict:
    labels = dict(host.labels or {}) if isinstance(host.labels, dict) else {}

    if hostname is not None and hostname != "":
        host.hostname = hostname
    if role is not None:
        labels["role"] = role
    if owner is not None:
        if owner != "":
            labels["owner"] = owner
        else:
            labels.pop("owner", None)
    if env is not None:
        labels["env_vars"] = dict(env)

        env_direct = None
        for k, v in env.items():
            if str(k).strip().lower() == "env":
                env_direct = str(v).strip()
                break
        if env_direct:
            labels["env"] = env_direct
        else:
            labels.pop("env", None)

    host.labels = labels
    return labels
