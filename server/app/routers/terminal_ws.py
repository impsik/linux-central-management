from __future__ import annotations

import logging
from contextlib import suppress
from datetime import datetime, timezone

from fastapi import APIRouter, WebSocket
from sqlalchemy import select

from ..config import settings
from ..db import SessionLocal
from ..deps import SESSION_COOKIE, sha256_hex
from ..models import AppSession, AppUser, Host
from ..services.hosts import resolve_host_target
from ..terminal_pipe import raw_pipe

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/ws", tags=["terminal"])


@router.websocket("/terminal/{agent_id}")
async def ws_terminal(ws: WebSocket, agent_id: str) -> None:
    await ws.accept()

    db = SessionLocal()
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

        host = db.execute(select(Host).where(Host.agent_id == agent_id)).scalar_one_or_none()
        if not host:
            await ws.close(code=1008, reason="Host not found")
            return

        # Enforce MFA for privileged roles before allowing terminal.
        role = (getattr(user, "role", "operator") or "operator").lower()
        require_mfa = bool(getattr(settings, "mfa_require_for_privileged", True)) and role in ("admin", "operator")
        if require_mfa:
            if not bool(getattr(user, "mfa_enabled", False)):
                await ws.send_text("\r\n[ERROR] MFA enrollment required before using terminal.\r\n")
                await ws.close(code=4403, reason="MFA enrollment required")
                return
            if not bool(getattr(sess, "mfa_verified_at", None)):
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

        allow_input = True

        if is_admin:
            allow_input = True
        elif role == "operator":
            # Operators can use terminal by default, like a VMware console.
            # Host label terminal_access can restrict it.
            if term_access in ("none", "disabled"):
                await ws.send_text("\r\n[ERROR] Terminal access denied for this host (terminal_access=none).\r\n")
                await ws.close(code=4403, reason="Terminal not allowed")
                return
            if term_access == "admin":
                await ws.send_text("\r\n[ERROR] Terminal access denied for this host (terminal_access=admin).\r\n")
                await ws.close(code=4403, reason="Terminal not allowed")
                return
            allow_input = True
        else:
            await ws.send_text("\r\n[ERROR] Terminal access is restricted.\r\n")
            await ws.close(code=4403, reason="Terminal not allowed")
            return

        connect_to = resolve_host_target(host)
        if not connect_to:
            await ws.close(code=1008, reason="Host has no reachable target")
            return

        scheme = getattr(settings, "agent_terminal_scheme", "ws")
        port = int(getattr(settings, "agent_terminal_port", 18080))
        agent_url = f"{scheme}://{connect_to}:{port}/terminal/ws"

        term_token = getattr(settings, "agent_terminal_token", None)
        if not term_token:
            await ws.send_text("\r\n[ERROR] Terminal is disabled on server (AGENT_TERMINAL_TOKEN not set).\r\n")
            await ws.close(code=1008, reason="Terminal disabled")
            return

        logger.info("Connecting to agent terminal: agent_id=%s url=%s", agent_id, agent_url)
        await raw_pipe(ws, agent_url, headers={"X-Fleet-Terminal-Token": term_token}, allow_input=allow_input)

    except Exception as e:
        logger.error("Error in ws_terminal: agent_id=%s err=%s", agent_id, e, exc_info=True)
        with suppress(Exception):
            await ws.close(code=1011, reason=f"Server error: {e}")
    finally:
        db.close()
