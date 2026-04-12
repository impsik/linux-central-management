from __future__ import annotations

from datetime import datetime, time, timezone
from zoneinfo import ZoneInfo

from fastapi.responses import JSONResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import settings
from ..models import AppMaintenanceWindow, Host


def _parse_hhmm(s: str, default: time) -> time:
    raw = (s or "").strip()
    if ":" not in raw:
        return default
    try:
        hh, mm = raw.split(":", 1)
        h = max(0, min(23, int(hh)))
        m = max(0, min(59, int(mm)))
        return time(hour=h, minute=m)
    except Exception:
        return default


def is_action_guarded(action: str) -> bool:
    guarded_csv = (getattr(settings, "maintenance_window_guarded_actions", "") or "").strip().lower()
    guarded = {x.strip() for x in guarded_csv.split(",") if x.strip()}
    return (action or "").strip().lower() in guarded


def _is_within_window(*, tz_name: str, start_hhmm: str, end_hhmm: str, now_utc: datetime | None = None) -> bool:
    try:
        tz = ZoneInfo((tz_name or "UTC").strip() or "UTC")
    except Exception:
        tz = timezone.utc

    now = (now_utc or datetime.now(timezone.utc)).astimezone(tz)
    start_t = _parse_hhmm(str(start_hhmm or "01:00"), time(1, 0))
    end_t = _parse_hhmm(str(end_hhmm or "05:00"), time(5, 0))

    cur = now.time()
    if start_t <= end_t:
        return start_t <= cur <= end_t

    return cur >= start_t or cur <= end_t


def is_within_maintenance_window(now_utc: datetime | None = None) -> bool:
    if not bool(getattr(settings, "maintenance_window_enabled", False)):
        return True

    return _is_within_window(
        tz_name=str(getattr(settings, "maintenance_window_timezone", "UTC") or "UTC"),
        start_hhmm=str(getattr(settings, "maintenance_window_start_hhmm", "01:00") or "01:00"),
        end_hhmm=str(getattr(settings, "maintenance_window_end_hhmm", "05:00") or "05:00"),
        now_utc=now_utc,
    )


def _window_matches_action(window: AppMaintenanceWindow, action: str) -> bool:
    actions = window.action_scope if isinstance(window.action_scope, list) else []
    normalized = {(str(x or "").strip().lower()) for x in actions if str(x or "").strip()}
    return not normalized or (action in normalized)


def _selector_matches_labels(selector: dict | None, labels: dict | None) -> bool:
    if not selector:
        return True
    hay = labels if isinstance(labels, dict) else {}
    for k, v in selector.items():
        if hay.get(k) != v:
            return False
    return True


def _scoped_windows_for_targets(db: Session, *, action: str, agent_ids: list[str] | None, labels: dict | None) -> list[AppMaintenanceWindow]:
    windows = db.execute(
        select(AppMaintenanceWindow).where(AppMaintenanceWindow.enabled == True)  # noqa: E712
    ).scalars().all()

    windows = [w for w in windows if _window_matches_action(w, action)]
    if not windows:
        return []

    if labels:
        return [w for w in windows if _selector_matches_labels(w.label_selector if isinstance(w.label_selector, dict) else {}, labels)]

    target_ids = [str(x).strip() for x in (agent_ids or []) if str(x).strip()]
    if not target_ids:
        return []

    hosts = db.execute(select(Host).where(Host.agent_id.in_(target_ids))).scalars().all()
    out: list[AppMaintenanceWindow] = []
    for w in windows:
        selector = w.label_selector if isinstance(w.label_selector, dict) else {}
        if not selector:
            out.append(w)
            continue
        if any(_selector_matches_labels(selector, h.labels if isinstance(h.labels, dict) else {}) for h in hosts):
            out.append(w)
    return out


def evaluate_action_now(action: str, *, db: Session | None = None, agent_ids: list[str] | None = None, labels: dict | None = None) -> dict:
    action_norm = (action or "").strip().lower()

    if db is not None:
        scoped = _scoped_windows_for_targets(db, action=action_norm, agent_ids=agent_ids, labels=labels)
        if scoped:
            matched_windows = [
                {
                    "id": str(w.id),
                    "name": w.name,
                    "timezone": w.timezone,
                    "start_hhmm": w.start_hhmm,
                    "end_hhmm": w.end_hhmm,
                    "enforcement_mode": w.enforcement_mode,
                    "label_selector": w.label_selector if isinstance(w.label_selector, dict) else {},
                    "action_scope": w.action_scope if isinstance(w.action_scope, list) else [],
                    "enabled": bool(w.enabled),
                }
                for w in scoped
            ]
            within = any(
                _is_within_window(
                    tz_name=str(w.timezone or "UTC"),
                    start_hhmm=str(w.start_hhmm or "01:00"),
                    end_hhmm=str(w.end_hhmm or "05:00"),
                )
                for w in scoped
            )
            if within:
                return {
                    "action": action_norm,
                    "decision": "allow",
                    "reason_code": "within_scoped_window",
                    "matched_count": len(matched_windows),
                    "matched_windows": matched_windows,
                }
            if any((str(w.enforcement_mode or "block").strip().lower() == "block") for w in scoped):
                return {
                    "action": action_norm,
                    "decision": "block",
                    "reason_code": "outside_scoped_window_blocked",
                    "matched_count": len(matched_windows),
                    "matched_windows": matched_windows,
                }
            return {
                "action": action_norm,
                "decision": "allow",
                "reason_code": "outside_scoped_window_warn_only",
                "matched_count": len(matched_windows),
                "matched_windows": matched_windows,
            }

    if not bool(getattr(settings, "maintenance_window_enabled", False)):
        return {
            "action": action_norm,
            "decision": "allow",
            "reason_code": "no_matching_scoped_window",
            "matched_count": 0,
            "matched_windows": [],
        }

    if not is_action_guarded(action_norm):
        return {
            "action": action_norm,
            "decision": "allow",
            "reason_code": "action_not_globally_guarded",
            "matched_count": 0,
            "matched_windows": [],
        }

    if is_within_maintenance_window():
        return {
            "action": action_norm,
            "decision": "allow",
            "reason_code": "within_global_window",
            "matched_count": 0,
            "matched_windows": [],
        }

    return {
        "action": action_norm,
        "decision": "block",
        "reason_code": "outside_global_window_blocked",
        "matched_count": 0,
        "matched_windows": [],
    }


def maintenance_block_detail(action: str, decision: dict | None = None) -> str:
    action_norm = (action or "").strip().lower()
    info = decision or {}
    if info.get("reason_code") == "outside_scoped_window_blocked":
        return f"Action '{action_norm}' is blocked outside maintenance window for matching targets"

    tz_name = (getattr(settings, "maintenance_window_timezone", "UTC") or "UTC").strip() or "UTC"
    start = str(getattr(settings, "maintenance_window_start_hhmm", "01:00") or "01:00")
    end = str(getattr(settings, "maintenance_window_end_hhmm", "05:00") or "05:00")
    return f"Action '{action_norm}' is blocked outside maintenance window ({start}-{end} {tz_name})"


def maintenance_block_response(action: str, decision: dict | None = None) -> JSONResponse:
    info = decision or {}
    return JSONResponse(
        status_code=403,
        content={
            "detail": maintenance_block_detail(action, info),
            "action": info.get("action") or (action or "").strip().lower(),
            "reason_code": info.get("reason_code") or "outside_global_window_blocked",
            "matched_count": int(info.get("matched_count") or 0),
            "matched_windows": info.get("matched_windows") or [],
        },
    )


def assert_action_allowed_now(action: str, *, db: Session | None = None, agent_ids: list[str] | None = None, labels: dict | None = None) -> None:
    decision = evaluate_action_now(action, db=db, agent_ids=agent_ids, labels=labels)
    if decision["decision"] != "block":
        return

    raise PermissionError(maintenance_block_detail(action, decision))
