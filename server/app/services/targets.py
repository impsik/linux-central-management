from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import Host


def resolve_agent_ids(db: Session, agent_ids: list[str] | None, labels: dict | None) -> list[str]:
    """Resolve targets from explicit agent_ids or label selectors."""
    if agent_ids:
        return agent_ids
    if labels:
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
        return out
    return []
