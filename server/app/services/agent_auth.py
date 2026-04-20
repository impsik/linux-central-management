from __future__ import annotations

from fastapi import HTTPException, Request

from ..config import settings

_LOOPBACK_HOSTS = {"127.0.0.1", "::1", "localhost", "testclient"}


def _request_is_loopback(request: Request) -> bool:
    host = str(getattr(getattr(request, "client", None), "host", "") or "").strip().lower()
    return host in _LOOPBACK_HOSTS


def require_agent_token(request: Request) -> None:
    expected = getattr(settings, "agent_shared_token", None)
    if not expected:
        if bool(getattr(settings, "allow_insecure_no_agent_token", False)) and _request_is_loopback(request):
            return
        raise HTTPException(401, "Agent token required")
    got = request.headers.get("X-Fleet-Agent-Token")
    if not got or got != expected:
        raise HTTPException(401, "Invalid agent token")


def require_agent_token_dep(request: Request) -> None:
    require_agent_token(request)
