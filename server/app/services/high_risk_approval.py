from __future__ import annotations

from ..config import settings


def is_approval_required(action: str) -> bool:
    if not bool(getattr(settings, "high_risk_approval_enabled", False)):
        return False
    action_norm = (action or "").strip().lower()
    allowed_csv = str(getattr(settings, "high_risk_approval_actions", "") or "")
    guarded = {x.strip().lower() for x in allowed_csv.split(",") if x.strip()}
    return action_norm in guarded
