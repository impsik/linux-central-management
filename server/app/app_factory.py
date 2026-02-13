from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, RedirectResponse
# NOTE: DB schema should be managed by Alembic in production.

from .db import Base, SessionLocal, engine
from .deps import get_current_user_from_request
from .routers import agent, ansible, audit, auth, cronjobs, dashboard, hosts, jobs, migrations, mfa, patching, reports, reports_html, search, sshkeys, terminal_ws, ui

logger = logging.getLogger(__name__)


def _startup() -> None:
    from .config import settings

    # Security guardrail: require AGENT_SHARED_TOKEN unless explicitly running insecure dev mode.
    if not getattr(settings, "agent_shared_token", None) and not bool(getattr(settings, "allow_insecure_no_agent_token", False)):
        raise RuntimeError(
            "AGENT_SHARED_TOKEN is required to start the server (agent endpoints would be unauthenticated). "
            "Set AGENT_SHARED_TOKEN or set ALLOW_INSECURE_NO_AGENT_TOKEN=true for local dev only."
        )

    if bool(getattr(settings, "db_auto_create_tables", True)):
        Base.metadata.create_all(bind=engine)
        logger.info("DB auto-create enabled: ensured database tables exist")

        # NOTE: legacy runtime migrations removed; use Alembic.
    else:
        logger.info("DB auto-create disabled: expecting schema to be managed by Alembic")
        if bool(getattr(settings, "db_require_migrations_up_to_date", True)):
            try:
                from .services.migrations_check import assert_db_up_to_date

                assert_db_up_to_date(engine)
                logger.info("Alembic migration status OK (DB is at head)")
            except Exception:
                # Fail fast to avoid confusing runtime errors.
                raise

    # Seed initial UI user (configurable via env)
    from passlib.context import CryptContext
    from sqlalchemy import select

    from .config import settings
    from .models import AppUser

    pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
    username = getattr(settings, "bootstrap_username", None) or "admin"
    password = getattr(settings, "bootstrap_password", None)
    if not password:
        logger.warning(
            "BOOTSTRAP_PASSWORD not set; not seeding initial UI user password. "
            "Set BOOTSTRAP_PASSWORD to enable initial user creation."
        )
        return

    db = SessionLocal()
    try:
        existing = db.execute(select(AppUser).where(AppUser.username == username)).scalar_one_or_none()
        if not existing:
            db.add(AppUser(username=username, password_hash=pwd_context.hash(password), role="admin", is_active=True))
            db.commit()
            logger.info(f"Seeded initial UI user '{username}'")
    except Exception as e:
        logger.error(f"Failed to seed initial UI user: {e}", exc_info=True)
        db.rollback()
    finally:
        db.close()


@asynccontextmanager
async def lifespan(app: FastAPI):
    _startup()

    # Background patch campaign dispatcher (best-effort)
    import asyncio

    from .services.patching import campaign_loop

    stop_event = asyncio.Event()
    task = asyncio.create_task(campaign_loop(stop_event))

    # Background cronjob dispatcher (one-shot scheduled jobs)
    try:
        from .services.cronjobs import cronjob_loop

        task2 = asyncio.create_task(cronjob_loop(stop_event))
        logger.info('Started cronjob dispatcher loop')
    except Exception:
        logger.exception('Failed to start cronjob dispatcher loop')

    # Background metrics refresher (keeps cached disk/load fresh)
    try:
        from .services.metrics_refresh import metrics_refresh_loop

        task3 = asyncio.create_task(metrics_refresh_loop(stop_event))
        logger.info('Started metrics refresh loop')
    except Exception:
        logger.exception('Failed to start metrics refresh loop')
        task3 = None

    try:
        yield
    finally:
        stop_event.set()
        task.cancel()
        try:
            task2.cancel()
        except Exception:
            pass
        try:
            if task3:
                task3.cancel()
        except Exception:
            pass
        try:
            await task
        except Exception:
            pass


def create_app() -> FastAPI:
    app = FastAPI(title="Fleet Ubuntu MVP", lifespan=lifespan)

    # CORS for separate-origin frontend. Off by default.
    from .config import settings

    if settings.cors_allow_origins or settings.cors_allow_origin_regex:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.cors_allow_origins,
            allow_origin_regex=settings.cors_allow_origin_regex,
            allow_methods=settings.cors_allow_methods,
            allow_headers=settings.cors_allow_headers,
            allow_credentials=bool(settings.cors_allow_credentials),
        )

    # Configure logging (keep MVP simple)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    @app.middleware("http")
    async def auth_middleware(request: Request, call_next):
        # Agents must be able to operate without UI auth
        path = request.url.path or ""
        if path.startswith("/agent/") or path == "/health" or path.startswith("/auth/") or path == "/login":
            return await call_next(request)

        # Allow unauthenticated access to websocket upgrade endpoints via their own handlers
        if path.startswith("/ws/"):
            return await call_next(request)

        db = SessionLocal()
        try:
            user = get_current_user_from_request(request, db)
            if not user:
                if path == "/":
                    return RedirectResponse(url="/login", status_code=302)
                return JSONResponse(status_code=401, content={"detail": "Not authenticated"})

            # MFA enforcement (required for admin/operator unless readonly).
            # Allow the UI shell and static assets so the user can complete MFA enrollment/verification flows.
            role = (getattr(user, "role", "operator") or "operator").lower()
            require_mfa = bool(getattr(settings, "mfa_require_for_privileged", True)) and role in ("admin", "operator")
            if require_mfa:
                # Always allow static assets and login shell.
                if path.startswith("/assets/") or path.startswith("/static/") or path in ("/", "/terminal"):
                    return await call_next(request)
                if any(path.endswith(ext) for ext in (".css", ".js", ".map", ".png", ".jpg", ".jpeg", ".svg", ".ico", ".woff", ".woff2", ".ttf")):
                    return await call_next(request)

                # Session is needed to check per-session verification.
                from .deps import get_current_session_from_request

                sess_res = get_current_session_from_request(request, db)
                mfa_enabled = bool(getattr(user, "mfa_enabled", False))
                mfa_verified = bool(sess_res and getattr(sess_res[0], "mfa_verified_at", None))

                if not mfa_enabled:
                    return JSONResponse(status_code=403, content={"detail": "MFA enrollment required"})
                if not mfa_verified:
                    return JSONResponse(status_code=403, content={"detail": "MFA verification required"})

            return await call_next(request)
        finally:
            db.close()

    @app.middleware("http")
    async def csrf_middleware(request: Request, call_next):
        """CSRF protection for cookie-authenticated requests.

        Double-submit cookie: require X-CSRF-Token to match fleet_csrf cookie
        on state-changing requests.
        """

        from .deps import CSRF_COOKIE, SESSION_COOKIE

        path = request.url.path or ""
        method = (request.method or "GET").upper()

        # Exemptions:
        # - agent endpoints use header token auth
        # - health check
        # - websockets
        # - login (no session yet)
        if path.startswith("/agent/") or path == "/health" or path.startswith("/ws/") or path == "/auth/login":
            return await call_next(request)

        if method in ("GET", "HEAD", "OPTIONS"):
            return await call_next(request)

        # Only enforce if a session cookie is present (UI auth uses cookies).
        if request.cookies.get(SESSION_COOKIE):
            csrf_cookie = request.cookies.get(CSRF_COOKIE)
            csrf_header = request.headers.get("X-CSRF-Token")
            if not csrf_cookie or not csrf_header or csrf_cookie != csrf_header:
                return JSONResponse(status_code=403, content={"detail": "CSRF token missing or invalid"})

        return await call_next(request)

    @app.middleware("http")
    async def security_headers_middleware(request: Request, call_next):
        """Set basic security headers.

        Kept intentionally conservative to avoid breaking the single-page UI.
        """

        from .config import settings

        resp = await call_next(request)

        if not bool(getattr(settings, "security_headers_enabled", True)):
            return resp

        # Basic hardening headers
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("Referrer-Policy", "same-origin")
        resp.headers.setdefault("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
        # Prevent clickjacking by default.
        resp.headers.setdefault("X-Frame-Options", "DENY")

        # HSTS only when behind HTTPS (or proxy indicates HTTPS) and cookie_secure is enabled.
        # Avoid setting this on HTTP dev deployments.
        xfp = (request.headers.get("x-forwarded-proto") or "").lower()
        is_https = (request.url.scheme == "https") or (xfp == "https")
        if is_https and bool(getattr(settings, "ui_cookie_secure", False)):
            resp.headers.setdefault("Strict-Transport-Security", "max-age=15552000")

        csp = getattr(settings, "content_security_policy", None)
        if csp:
            resp.headers.setdefault("Content-Security-Policy", str(csp))

        return resp

    # Routers
    app.include_router(ui.router)
    app.include_router(auth.router)
    app.include_router(mfa.router)
    app.include_router(audit.router)
    app.include_router(agent.router)
    app.include_router(dashboard.router)
    app.include_router(cronjobs.router)
    app.include_router(sshkeys.router)
    app.include_router(hosts.router)
    app.include_router(reports.router)
    app.include_router(reports_html.router)
    app.include_router(jobs.router)
    app.include_router(ansible.router)
    from .config import settings
    if bool(getattr(settings, "admin_enable_migrations_endpoint", False)):
        app.include_router(migrations.router)
    app.include_router(search.router)
    app.include_router(patching.router)
    app.include_router(terminal_ws.router)

    # Simple health endpoint
    @app.get("/health")
    def health():
        return {"ok": True, "service": "fleet-server", "ts": datetime.now(timezone.utc).isoformat()}

    return app
