from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, Request
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session

from ..db import get_db
from ..deps import get_current_user_from_request, require_ui_user
from ..models import AppUser

router = APIRouter(tags=["ui"])

TEMPLATES_DIR = Path(__file__).resolve().parents[1] / "templates"


def _read_template(name: str) -> str:
    path = (TEMPLATES_DIR / name).resolve()
    # Basic safety: prevent path traversal
    if TEMPLATES_DIR not in path.parents:
        raise ValueError("Invalid template path")
    return path.read_text(encoding="utf-8", errors="ignore")


@router.get("/login", response_class=HTMLResponse)
def login_page():
    return _read_template("login.html")


@router.get("/assets/index-MnFIflNy.css")
def ui_css():
    return FileResponse(str(TEMPLATES_DIR / "index-MnFIflNy.css"), media_type="text/css")


@router.get("/assets/fleet-ui.css")
def ui_custom_css():
    return FileResponse(str(TEMPLATES_DIR / "fleet-ui.css"), media_type="text/css")


@router.get("/assets/fleet-phase3.js")
def ui_phase3_js():
    return FileResponse(str(TEMPLATES_DIR / "fleet-phase3.js"), media_type="application/javascript")


@router.get("/terminal", response_class=HTMLResponse)
def terminal_popup_page(request: Request, user: AppUser = Depends(require_ui_user)):
    return _read_template("terminal_popup.html")


@router.get("/", response_class=HTMLResponse)
def ui(request: Request, db: Session = Depends(get_db)):
    user = get_current_user_from_request(request, db)
    if not user:
        return RedirectResponse(url="/login", status_code=302)

    # Avoid caching during rapid UI iteration; otherwise browsers may keep old JS.
    return HTMLResponse(
        content=_read_template("index.html"),
        headers={"Cache-Control": "no-store"},
    )
