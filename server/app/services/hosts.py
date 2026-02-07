from __future__ import annotations

from datetime import datetime, timezone

from .types import JSONDict
from ..config import settings
from ..models import Host


def is_host_online(host: Host, now: datetime | None = None) -> bool:
    if not host or not host.last_seen:
        return False
    if now is None:
        now = datetime.now(timezone.utc)
    try:
        return (now - host.last_seen).total_seconds() <= settings.agent_online_grace_seconds
    except Exception:
        return False


def seconds_since_seen(host: Host, now: datetime | None = None) -> float | None:
    if not host or not host.last_seen:
        return None
    if now is None:
        now = datetime.now(timezone.utc)
    try:
        return (now - host.last_seen).total_seconds()
    except Exception:
        return None


def resolve_host_target(host: Host) -> str | None:
    # Prefer IP address for connection (most reliable), then fqdn, then hostname
    ip_address = getattr(host, "ip_address", None)
    if ip_address:
        return ip_address
    if host.fqdn:
        return host.fqdn
    if host.hostname:
        return host.hostname
    return host.agent_id
