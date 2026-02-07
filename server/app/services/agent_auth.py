from __future__ import annotations

from fastapi import HTTPException, Request

from ..config import settings


def require_agent_token(request: Request) -> None:
    expected = getattr(settings, "agent_shared_token", None)
    if not expected:
        return
    got = request.headers.get("X-Fleet-Agent-Token")
    if not got or got != expected:
        raise HTTPException(401, "Invalid agent token")
