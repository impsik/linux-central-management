from __future__ import annotations

from fastapi import Depends, HTTPException, Request
from sqlalchemy.orm import Session

from ..config import settings
from ..db import get_db
from .audit import log_event

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


def _log_agent_auth_failure(db: Session, request: Request, reason: str) -> None:
    try:
        log_event(
            db,
            action="agent.auth.failed",
            actor=None,
            request=request,
            target_type="agent_api",
            meta={
                "reason": reason,
                "path": str(getattr(getattr(request, "url", None), "path", "") or ""),
            },
        )
        db.commit()
    except Exception:
        try:
            db.rollback()
        except Exception:
            pass


def require_agent_token_dep(request: Request, db: Session = Depends(get_db)) -> None:
    try:
        require_agent_token(request)
    except HTTPException as exc:
        _log_agent_auth_failure(db, request, str(exc.detail or "invalid_agent_token"))
        raise
