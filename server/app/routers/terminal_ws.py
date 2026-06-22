from __future__ import annotations

import logging
from contextlib import suppress
from datetime import datetime, timezone
from urllib.parse import urlparse

from fastapi import APIRouter, WebSocket
from sqlalchemy import select

from ..config import settings
from ..db import SessionLocal
from ..deps import SESSION_COOKIE, sha256_hex
from ..models import AppSession, AppUser, Host
from ..services.audit import log_event
from ..services.hosts import resolve_host_target
from ..services.user_scopes import is_host_visible_to_user
from ..terminal_pipe import raw_pipe

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/ws", tags=["terminal"])


def _split_host(value: str | None) -> str:
    return str(value or "").split(",", 1)[0].strip().lower()


def _websocket_origin_allowed(headers) -> bool:
    origin = _split_host(headers.get("origin"))
    if not origin:
        # Non-browser clients normally omit Origin. Browser clients send it.
        return True

    try:
        parsed_origin = urlparse(origin)
    except Exception:
        return False
    if parsed_origin.scheme not in {"http", "https"} or not parsed_origin.netloc:
        return False

    allowed_hosts = {
        _split_host(headers.get("host")),
        _split_host(headers.get("x-forwarded-host")),
    }
    allowed_hosts.discard("")

    return parsed_origin.netloc.lower() in allowed_hosts


def _terminal_ws_meta(ws: WebSocket, *, role: str | None = None, term_access: str | None = None, reason: str | None = None) -> dict:
    meta = {
        "client_host": str(getattr(getattr(ws, "client", None), "host", "") or ""),
        "origin": str(ws.headers.get("origin") or ""),
        "host": str(ws.headers.get("host") or ""),
    }
    if role:
        meta["role"] = role
    if term_access:
        meta["terminal_access"] = term_access
    if reason:
        meta["reason"] = reason
    return meta


def _audit_terminal_event(
    db,
    *,
    action: str,
    user: AppUser | None,
    host: Host | None,
    agent_id: str,
    ws: WebSocket,
    role: str | None = None,
    term_access: str | None = None,
    reason: str | None = None,
    connect_target: str | None = None,
) -> None:
    meta = _terminal_ws_meta(ws, role=role, term_access=term_access, reason=reason)
    if connect_target:
        meta["connect_target"] = connect_target
    log_event(
        db,
        action=action,
        actor=user,
        request=None,
        target_type="host",
        target_id=str(getattr(host, "agent_id", None) or agent_id or ""),
        target_name=str(getattr(host, "hostname", None) or agent_id or ""),
        meta=meta,
    )
    try:
        db.commit()
    except Exception:
        db.rollback()


@router.websocket("/terminal/{agent_id}")
async def ws_terminal(ws: WebSocket, agent_id: str) -> None:
    if not _websocket_origin_allowed(ws.headers):
        await ws.close(code=1008, reason="Invalid Origin")
        return

    await ws.accept()

    db = SessionLocal()
    audit_user: AppUser | None = None
    audit_host: Host | None = None
    audit_role: str | None = None
    audit_term_access: str | None = None
    audit_connect_to: str | None = None
    try:
        token = getattr(ws, "cookies", {}).get(SESSION_COOKIE)
        if not token:
            await ws.close(code=4401, reason="Not authenticated")
            return

        token_hash = sha256_hex(token)
        now = datetime.now(timezone.utc)

        sess = db.execute(
            select(AppSession).where(AppSession.token_sha256 == token_hash, AppSession.expires_at > now)
        ).scalar_one_or_none()
        if not sess:
            await ws.close(code=4401, reason="Not authenticated")
            return

        user = db.execute(
            select(AppUser).where(AppUser.id == sess.user_id, AppUser.is_active == True)  # noqa: E712
        ).scalar_one_or_none()
        if not user:
            await ws.close(code=4401, reason="Not authenticated")
            return
        audit_user = user

        host = db.execute(select(Host).where(Host.agent_id == agent_id)).scalar_one_or_none()
        if not host:
            _audit_terminal_event(
                db,
                action="terminal.session.denied",
                user=user,
                host=None,
                agent_id=agent_id,
                ws=ws,
                reason="host_not_found",
            )
            await ws.close(code=1008, reason="Host not found")
            return
        audit_host = host
        if not is_host_visible_to_user(db, user, host):
            _audit_terminal_event(
                db,
                action="terminal.session.denied",
                user=user,
                host=host,
                agent_id=agent_id,
                ws=ws,
                reason="host_out_of_scope",
            )
            await ws.close(code=4403, reason="Host out of scope")
            return

        # Enforce MFA for privileged roles before allowing terminal.
        role = (getattr(user, "role", "operator") or "operator").lower()
        audit_role = role
        require_mfa = bool(getattr(settings, "mfa_require_for_privileged", True)) and role in ("admin", "operator")
        if require_mfa:
            if not bool(getattr(user, "mfa_enabled", False)):
                _audit_terminal_event(
                    db,
                    action="terminal.session.denied",
                    user=user,
                    host=host,
                    agent_id=agent_id,
                    ws=ws,
                    role=role,
                    reason="mfa_enrollment_required",
                )
                await ws.send_text("\r\n[ERROR] MFA enrollment required before using terminal.\r\n")
                await ws.close(code=4403, reason="MFA enrollment required")
                return
            if not bool(getattr(sess, "mfa_verified_at", None)):
                _audit_terminal_event(
                    db,
                    action="terminal.session.denied",
                    user=user,
                    host=host,
                    agent_id=agent_id,
                    ws=ws,
                    role=role,
                    reason="mfa_verification_required",
                )
                await ws.send_text("\r\n[ERROR] MFA verification required before using terminal.\r\n")
                await ws.close(code=4403, reason="MFA verification required")
                return

        # Terminal is a high-risk feature.
        # Policy (team "console" model):
        # - admin: full terminal
        # - operator: full terminal by default
        # - readonly: no terminal
        # Hosts can opt-out via host label terminal_access=admin|none.
        admin_username = (getattr(settings, "bootstrap_username", None) or "").strip()
        role = getattr(user, "role", "") or "operator"
        is_admin = (role == "admin") or (admin_username and user.username == admin_username)

        host_labels = (host.labels or {}) if hasattr(host, "labels") else {}
        term_access = str(host_labels.get("terminal_access") or "all").strip().lower()
        audit_term_access = term_access

        allow_input = True

        if is_admin:
            allow_input = True
        elif role == "operator":
            # Operators can use terminal by default, like a VMware console.
            # Host label terminal_access can restrict it.
            if term_access in ("none", "disabled"):
                _audit_terminal_event(
                    db,
                    action="terminal.session.denied",
                    user=user,
                    host=host,
                    agent_id=agent_id,
                    ws=ws,
                    role=role,
                    term_access=term_access,
                    reason="terminal_access_none",
                )
                await ws.send_text("\r\n[ERROR] Terminal access denied for this host (terminal_access=none).\r\n")
                await ws.close(code=4403, reason="Terminal not allowed")
                return
            if term_access == "admin":
                _audit_terminal_event(
                    db,
                    action="terminal.session.denied",
                    user=user,
                    host=host,
                    agent_id=agent_id,
                    ws=ws,
                    role=role,
                    term_access=term_access,
                    reason="terminal_access_admin",
                )
                await ws.send_text("\r\n[ERROR] Terminal access denied for this host (terminal_access=admin).\r\n")
                await ws.close(code=4403, reason="Terminal not allowed")
                return
            allow_input = True
        else:
            _audit_terminal_event(
                db,
                action="terminal.session.denied",
                user=user,
                host=host,
                agent_id=agent_id,
                ws=ws,
                role=role,
                term_access=term_access,
                reason="role_not_allowed",
            )
            await ws.send_text("\r\n[ERROR] Terminal access is restricted.\r\n")
            await ws.close(code=4403, reason="Terminal not allowed")
            return

        connect_to = resolve_host_target(host)
        audit_connect_to = connect_to
        if not connect_to:
            _audit_terminal_event(
                db,
                action="terminal.session.denied",
                user=user,
                host=host,
                agent_id=agent_id,
                ws=ws,
                role=role,
                term_access=term_access,
                reason="no_reachable_target",
            )
            await ws.close(code=1008, reason="Host has no reachable target")
            return

        scheme = getattr(settings, "agent_terminal_scheme", "ws")
        port = int(getattr(settings, "agent_terminal_port", 18080))
        agent_url = f"{scheme}://{connect_to}:{port}/terminal/ws"

        term_token = getattr(settings, "agent_terminal_token", None)
        if not term_token:
            _audit_terminal_event(
                db,
                action="terminal.session.denied",
                user=user,
                host=host,
                agent_id=agent_id,
                ws=ws,
                role=role,
                term_access=term_access,
                reason="terminal_disabled",
            )
            await ws.send_text("\r\n[ERROR] Terminal is disabled on server (AGENT_TERMINAL_TOKEN not set).\r\n")
            await ws.close(code=1008, reason="Terminal disabled")
            return

        logger.info("Connecting to agent terminal: agent_id=%s url=%s", agent_id, agent_url)
        _audit_terminal_event(
            db,
            action="terminal.session.opened",
            user=user,
            host=host,
            agent_id=agent_id,
            ws=ws,
            role=role,
            term_access=term_access,
            connect_target=connect_to,
        )
        await raw_pipe(ws, agent_url, headers={"X-Fleet-Terminal-Token": term_token}, allow_input=allow_input)
        _audit_terminal_event(
            db,
            action="terminal.session.closed",
            user=user,
            host=host,
            agent_id=agent_id,
            ws=ws,
            role=role,
            term_access=term_access,
            connect_target=connect_to,
        )

    except Exception as e:
        _audit_terminal_event(
            db,
            action="terminal.session.error",
            user=audit_user,
            host=audit_host,
            agent_id=agent_id,
            ws=ws,
            role=audit_role,
            term_access=audit_term_access,
            reason=type(e).__name__,
            connect_target=audit_connect_to,
        )
        logger.error("Error in ws_terminal: agent_id=%s err=%s", agent_id, e, exc_info=True)
        with suppress(Exception):
            await ws.close(code=1011, reason=f"Server error: {e}")
    finally:
        db.close()
