from __future__ import annotations

import mimetypes
from pathlib import Path


from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session

from ..db import get_db
from ..deps import get_current_user_from_request, require_ui_user
from ..models import AppUser

router = APIRouter(tags=["ui"])

TEMPLATES_DIR = Path(__file__).resolve().parents[1] / "templates"


def _compute_asset_version() -> str:
    """Build a stable per-process cache-busting token from template asset mtimes."""
    latest_mtime_ns = 0
    try:
        for p in TEMPLATES_DIR.glob("*"):
            if p.is_file() and p.suffix.lower() in (".js", ".css"):
                try:
                    latest_mtime_ns = max(latest_mtime_ns, int(p.stat().st_mtime_ns))
                except Exception:
                    continue
    except Exception:
        latest_mtime_ns = 0
    # Keep token short for URLs.
    return str(latest_mtime_ns or 1)


ASSET_VERSION = _compute_asset_version()


def _read_template(name: str) -> str:
    path = (TEMPLATES_DIR / name).resolve()
    # Basic safety: prevent path traversal
    if TEMPLATES_DIR not in path.parents:
        raise ValueError("Invalid template path")
    return path.read_text(encoding="utf-8", errors="ignore")


def _render_template_with_nonce(name: str, request: Request) -> str:
    html = _read_template(name)
    html = html.replace("__ASSET_VERSION__", ASSET_VERSION)
    nonce = getattr(getattr(request, "state", None), "csp_nonce", None)
    if nonce:
        return html.replace("__CSP_NONCE__", str(nonce))
    return html.replace(' nonce="__CSP_NONCE__"', "")


@router.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return HTMLResponse(
        content=_render_template_with_nonce("login.html", request),
        headers={"Cache-Control": "no-store"},
    )


@router.get("/assets/index-MnFIflNy.css")
def ui_css():
    return FileResponse(str(TEMPLATES_DIR / "index-MnFIflNy.css"), media_type="text/css")


@router.get("/assets/fleet-ui.css")
def ui_custom_css():
    return FileResponse(str(TEMPLATES_DIR / "fleet-ui.css"), media_type="text/css")


@router.get("/assets/fleet-theme-bootstrap.js")
def ui_theme_bootstrap_js():
    return FileResponse(str(TEMPLATES_DIR / "fleet-theme-bootstrap.js"), media_type="application/javascript")


@router.get("/assets/fleet-phase3.js")
def ui_phase3_js():
    return FileResponse(str(TEMPLATES_DIR / "fleet-phase3.js"), media_type="application/javascript")


@router.get("/assets/{asset_path:path}")
def ui_asset_file(asset_path: str):
    # Serve additional UI assets from templates/ without adding one route per file.
    requested = (TEMPLATES_DIR / asset_path).resolve()
    if TEMPLATES_DIR not in requested.parents:
        raise HTTPException(status_code=404, detail="Asset not found")
    if not requested.is_file():
        raise HTTPException(status_code=404, detail="Asset not found")

    media_type, _ = mimetypes.guess_type(str(requested))
    return FileResponse(str(requested), media_type=media_type)


@router.get("/terminal", response_class=HTMLResponse)
def terminal_popup_page(request: Request, user: AppUser = Depends(require_ui_user)):
    return _render_template_with_nonce("terminal_popup.html", request)


@router.get("/", response_class=HTMLResponse)
def ui(request: Request, db: Session = Depends(get_db)):
    user = get_current_user_from_request(request, db)
    if not user:
        return RedirectResponse(url="/login", status_code=302)

    # Avoid caching during rapid UI iteration; otherwise browsers may keep old JS.
    return HTMLResponse(
        content=_render_template_with_nonce("index.html", request),
        headers={"Cache-Control": "no-store"},
    )
