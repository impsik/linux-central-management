from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import AppUser, AppUserScope, Host
from .rbac import is_admin


def _normalize_selector(raw: dict | None) -> dict[str, list[str]]:
    if not isinstance(raw, dict):
        return {}
    out: dict[str, list[str]] = {}
    for k, v in raw.items():
        key = str(k or "").strip()
        if not key:
            continue
        vals: list[str] = []
        if isinstance(v, list):
            vals = [str(x).strip() for x in v if str(x).strip()]
        elif v is not None:
            vv = str(v).strip()
            if vv:
                vals = [vv]
        if vals:
            out[key] = sorted(list(set(vals)))
    return out


def get_user_scope_selectors(db: Session, user: AppUser) -> list[dict[str, list[str]]]:
    if is_admin(user):
        return []

    rows = db.execute(
        select(AppUserScope)
        .where(AppUserScope.user_id == user.id, AppUserScope.scope_type == "label_selector")
        .order_by(AppUserScope.created_at.asc())
    ).scalars().all()

    selectors: list[dict[str, list[str]]] = []
    for r in rows:
        norm = _normalize_selector(getattr(r, "selector", {}) or {})
        if norm:
            selectors.append(norm)
    return selectors


def user_has_scope_limits(db: Session, user: AppUser) -> bool:
    if is_admin(user):
        return False
    n = db.execute(
        select(AppUserScope.id).where(AppUserScope.user_id == user.id, AppUserScope.scope_type == "label_selector").limit(1)
    ).first()
    return bool(n)


def is_host_visible_to_user(db: Session, user: AppUser, host: Host) -> bool:
    if is_admin(user):
        return True
    selectors = get_user_scope_selectors(db, user)
    if not selectors:
        return True

    labels = (getattr(host, "labels", None) or {}) if host is not None else {}
    for sel in selectors:
        ok = True
        for k, allowed in sel.items():
            if str(labels.get(k, "")).strip() not in allowed:
                ok = False
                break
        if ok:
            return True
    return False


def filter_agent_ids_for_user(db: Session, user: AppUser, agent_ids: list[str]) -> list[str]:
    if is_admin(user):
        return sorted(list(set([a for a in agent_ids if a])))

    selectors = get_user_scope_selectors(db, user)
    uniq = sorted(list(set([a for a in agent_ids if a])))
    if not selectors:
        return uniq

    hosts = db.execute(select(Host).where(Host.agent_id.in_(uniq))).scalars().all()
    host_by_agent = {h.agent_id: h for h in hosts}

    out: list[str] = []
    for aid in uniq:
        h = host_by_agent.get(aid)
        if h and is_host_visible_to_user(db, user, h):
            out.append(aid)
    return out
