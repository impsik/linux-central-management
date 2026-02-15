from __future__ import annotations

from datetime import datetime, time, timezone
from zoneinfo import ZoneInfo

from ..config import settings


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


def is_within_maintenance_window(now_utc: datetime | None = None) -> bool:
    if not bool(getattr(settings, "maintenance_window_enabled", False)):
        return True

    tz_name = (getattr(settings, "maintenance_window_timezone", "UTC") or "UTC").strip() or "UTC"
    try:
        tz = ZoneInfo(tz_name)
    except Exception:
        tz = timezone.utc

    now = (now_utc or datetime.now(timezone.utc)).astimezone(tz)

    start_t = _parse_hhmm(str(getattr(settings, "maintenance_window_start_hhmm", "01:00") or "01:00"), time(1, 0))
    end_t = _parse_hhmm(str(getattr(settings, "maintenance_window_end_hhmm", "05:00") or "05:00"), time(5, 0))

    cur = now.time()
    if start_t <= end_t:
        return start_t <= cur <= end_t

    # overnight windows (e.g. 23:00-03:00)
    return cur >= start_t or cur <= end_t


def assert_action_allowed_now(action: str) -> None:
    if not bool(getattr(settings, "maintenance_window_enabled", False)):
        return

    action_norm = (action or "").strip().lower()
    if not is_action_guarded(action_norm):
        return

    if is_within_maintenance_window():
        return

    tz_name = (getattr(settings, "maintenance_window_timezone", "UTC") or "UTC").strip() or "UTC"
    start = str(getattr(settings, "maintenance_window_start_hhmm", "01:00") or "01:00")
    end = str(getattr(settings, "maintenance_window_end_hhmm", "05:00") or "05:00")
    raise PermissionError(
        f"Action '{action_norm}' is blocked outside maintenance window ({start}-{end} {tz_name})"
    )
