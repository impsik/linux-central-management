from __future__ import annotations

from fastapi import APIRouter
from fastapi.responses import HTMLResponse

router = APIRouter(tags=["ui"])


@router.get("/hosts-table", response_class=HTMLResponse)
def hosts_table_page():
    # Simple redirect to main UI; table is rendered in index.html for now.
    return HTMLResponse("<html><head><meta http-equiv='refresh' content='0; url=/' /></head><body>Redirecting…</body></html>")
