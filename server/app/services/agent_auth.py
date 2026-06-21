from __future__ import annotations

import hashlib
import hmac

from fastapi import Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import settings
from ..db import get_db
from ..models import Host
from .audit import log_event

_LOOPBACK_HOSTS = {"127.0.0.1", "::1", "localhost", "testclient"}


def _request_is_loopback(request: Request) -> bool:
    host = str(getattr(getattr(request, "client", None), "host", "") or "").strip().lower()
    return host in _LOOPBACK_HOSTS


def hash_agent_token(token: str) -> str:
    return hashlib.sha256(str(token or "").encode("utf-8")).hexdigest()


def _safe_equal(left: str | None, right: str | None) -> bool:
    if not left or not right:
        return False
    return hmac.compare_digest(str(left), str(right))


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
    got = request.headers.get("X-Fleet-Agent-Token")
    expected = getattr(settings, "agent_shared_token", None)
    if expected and _safe_equal(got, expected):
        path = str(getattr(getattr(request, "url", None), "path", "") or "")
        if path != "/agent/register" and not bool(getattr(settings, "agent_shared_token_allow_runtime", False)):
            _log_agent_auth_failure(db, request, "shared_token_not_allowed_for_runtime")
            raise HTTPException(403, "Shared agent token is only valid for registration")
        request.state.agent_auth_kind = "shared"
        request.state.agent_auth_agent_id = None
        return

    agent_id = str(request.headers.get("X-Fleet-Agent-ID") or "").strip()
    if got and agent_id:
        host = db.execute(select(Host).where(Host.agent_id == agent_id)).scalar_one_or_none()
        expected_hash = getattr(host, "agent_token_hash", None) if host else None
        if expected_hash and _safe_equal(hash_agent_token(got), expected_hash):
            request.state.agent_auth_kind = "per_agent"
            request.state.agent_auth_agent_id = agent_id
            return

    try:
        require_agent_token(request)
    except HTTPException as exc:
        _log_agent_auth_failure(db, request, str(exc.detail or "invalid_agent_token"))
        raise
