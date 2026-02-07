from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from ..db import get_db
from ..deps import require_ui_user
from ..routers.reports import hosts_updates_report

router = APIRouter(prefix="/reports", tags=["reports"])


@router.get("/hosts-updates.html", response_class=HTMLResponse)
def hosts_updates_html(
    only_pending: bool = True,
    online_only: bool = False,
    sort: str = "security_updates",
    order: str = "desc",
    db: Session = Depends(get_db),
    user=Depends(require_ui_user),
):
    data = hosts_updates_report(
        only_pending=only_pending,
        online_only=online_only,
        sort=sort,
        order=order,
        limit=5000,
        offset=0,
        db=db,
        user=user,
    )

    now = datetime.now(timezone.utc)
    ts = now.isoformat()

    def esc(s: str) -> str:
        return (
            str(s)
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
        )

    rows = data.get("items") or []

    html_rows = []
    for r in rows:
        host = esc(r.get("hostname") or r.get("agent_id") or "")
        agent_id = esc(r.get("agent_id") or "")
        ip = esc(r.get("ip_address") or "")
        os_name = esc(((r.get("os_id") or "") + " " + (r.get("os_version") or "")).strip() or "-")
        kernel = esc(r.get("kernel") or "-")
        sec = int(r.get("security_updates") or 0)
        upd = int(r.get("updates") or 0)
        online = "online" if r.get("is_online") else "offline"
        last_seen = esc(r.get("last_seen") or "")

        html_rows.append(
            f"<tr>"
            f"<td><b>{host}</b><div class='muted'>{agent_id}{(' • ' + ip) if ip else ''}</div></td>"
            f"<td>{os_name}</td>"
            f"<td><code>{kernel}</code></td>"
            f"<td class='num'>{sec}</td>"
            f"<td class='num'>{upd}</td>"
            f"<td><span class='pill {online}'>{online}</span></td>"
            f"<td class='muted'>{last_seen}</td>"
            f"</tr>"
        )

    body = "\n".join(html_rows) if html_rows else "<tr><td colspan='7' class='muted'>No rows</td></tr>"

    def toggle_order(for_sort: str) -> str:
        if (sort or "") == for_sort:
            return "asc" if (order or "").lower() == "desc" else "desc"
        return "desc"

    def sort_link(label: str, key: str) -> str:
        next_order = toggle_order(key)
        arrow = ""
        if (sort or "") == key:
            arrow = " ▼" if (order or "").lower() == "desc" else " ▲"
        href = (
            f"/reports/hosts-updates.html?only_pending={str(only_pending).lower()}"
            f"&online_only={str(online_only).lower()}&sort={key}&order={next_order}"
        )
        return f"<a href='{esc(href)}' style='color:inherit;text-decoration:none;'>{esc(label)}{arrow}</a>"

    filename = f"pending-updates-{now.strftime('%Y%m%d-%H%M%S')}Z.html"

    return HTMLResponse(
        content=f"""<!doctype html>
<html>
<head>
  <meta charset='utf-8' />
  <title>Fleet Report - Pending Updates</title>
  <style>
    body {{ font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Ubuntu, Cantarell, Noto Sans, Arial; padding: 24px; color:#0f172a; }}
    h1 {{ margin: 0 0 6px 0; }}
    .meta {{ color:#475569; margin-bottom: 16px; }}
    table {{ border-collapse: collapse; width: 100%; min-width: 900px; }}
    th, td {{ border-bottom: 1px solid #e2e8f0; padding: 10px 8px; text-align: left; vertical-align: top; }}
    th {{ background: #f8fafc; position: sticky; top: 0; }}
    th a:hover {{ text-decoration: underline; }}
    .muted {{ color:#64748b; font-size: 12px; margin-top: 2px; }}
    .num {{ text-align: right; font-variant-numeric: tabular-nums; }}
    code {{ background:#f1f5f9; padding: 2px 6px; border-radius: 6px; }}
    .pill {{ display:inline-block; padding: 2px 8px; border-radius: 999px; font-size: 12px; }}
    .pill.online {{ background:#dcfce7; color:#166534; }}
    .pill.offline {{ background:#fee2e2; color:#991b1b; }}
    .wrap {{ overflow-x:auto; }}
  </style>
</head>
<body>
  <h1>Pending Updates Report</h1>
  <div class='meta'>Generated: {esc(ts)} UTC • only_pending={esc(str(only_pending))} • online_only={esc(str(online_only))} • sort={esc(sort)} {esc(order)} • rows={len(rows)}</div>
  <div class='wrap'>
    <table>
      <thead>
        <tr>
          <th>{sort_link('Host','hostname')}</th>
          <th>{sort_link('OS','os_version')}</th>
          <th>{sort_link('Kernel','kernel')}</th>
          <th class='num'>{sort_link('Security','security_updates')}</th>
          <th class='num'>{sort_link('All updates','updates')}</th>
          <th>Online</th>
          <th>{sort_link('Last seen','last_seen')}</th>
        </tr>
      </thead>
      <tbody>
        {body}
      </tbody>
    </table>
  </div>
</body>
</html>""",
        media_type="text/html",
        headers={"Cache-Control": "no-store"},
    )
