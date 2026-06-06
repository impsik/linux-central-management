from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends

from ..config import settings
from ..deps import require_ui_user
from ..services.maintenance import is_action_guarded, is_within_maintenance_window

router = APIRouter(prefix="/maintenance-windows", tags=["maintenance-windows"])


@router.post("/evaluate")
def evaluate_maintenance_window(payload: dict, user=Depends(require_ui_user)):
    action = str((payload or {}).get("action") or "").strip().lower()
    agent_ids = [str(a).strip() for a in ((payload or {}).get("agent_ids") or []) if str(a).strip()]
    enabled = bool(getattr(settings, "maintenance_window_enabled", False))
    guarded = is_action_guarded(action)
    within = bool(is_within_maintenance_window())
    timezone_name = str(getattr(settings, "maintenance_window_timezone", "UTC") or "UTC")
    start = str(getattr(settings, "maintenance_window_start_hhmm", "01:00") or "01:00")
    end = str(getattr(settings, "maintenance_window_end_hhmm", "05:00") or "05:00")

    matched_windows = []
    if enabled and guarded:
        matched_windows.append({
            "name": "Configured maintenance window",
            "timezone": timezone_name,
            "start": start,
            "end": end,
            "agent_count": len(agent_ids),
        })

    blocked = bool(enabled and guarded and not within)
    return {
        "decision": "block" if blocked else "allow",
        "action": action,
        "enabled": enabled,
        "guarded": guarded,
        "within_window_now": within,
        "matched_windows": matched_windows if blocked else [],
        "ts": datetime.now(timezone.utc).isoformat(),
    }
