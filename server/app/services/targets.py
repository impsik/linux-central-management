from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import AppUser, Host
from .user_scopes import filter_agent_ids_for_user


def resolve_agent_ids(db: Session, agent_ids: list[str] | None, labels: dict | None, user: AppUser | None = None) -> list[str]:
    """Resolve targets from explicit agent_ids or label selectors.

    If `user` is provided, resolved targets are intersected with user scope limits.
    """
    if agent_ids:
        resolved = [str(a).strip() for a in agent_ids if str(a).strip()]
    elif labels:
        hosts = db.execute(select(Host)).scalars().all()
        out: list[str] = []
        for h in hosts:
            ok = True
            for k, v in labels.items():
                if (h.labels or {}).get(k) != v:
                    ok = False
                    break
            if ok:
                out.append(h.agent_id)
        resolved = out
    else:
        resolved = []

    if user is None:
        return resolved

    return filter_agent_ids_for_user(db, user, resolved)
