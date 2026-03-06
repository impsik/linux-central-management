from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Query
from fastapi.responses import HTMLResponse
from sqlalchemy import select, func, delete
from sqlalchemy.orm import Session

from ..db import get_db
from ..deps import require_ui_user
from ..models import Host, HostUser
from ..routers.reports import hosts_updates_report
from ..services.db_utils import transaction
from ..services.hosts import is_host_online
from ..services.job_wait import wait_for_job_run
from ..services.jobs import create_job_with_runs, push_job_to_agents
from ..services.json_utils import loads_or
from ..services.user_scopes import is_host_visible_to_user

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
  <script src='/assets/fleet-theme-bootstrap.js'></script>
  <style>
    :root {{ --bg:#ffffff; --text:#0f172a; --muted:#475569; --muted2:#64748b; --border:#e2e8f0; --th:#f8fafc; --code:#f1f5f9; --btn:#ffffff; }}
    :root[data-theme="dark"] {{ --bg:#0b1220; --text:#e2e8f0; --muted:#cbd5e1; --muted2:#94a3b8; --border:#334155; --th:#111827; --code:#0f172a; --btn:#111827; }}
    body {{ font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Ubuntu, Cantarell, Noto Sans, Arial; padding: 24px; color:var(--text); background:var(--bg); }}
    h1 {{ margin: 0 0 6px 0; }}
    .meta {{ color:var(--muted); margin-bottom: 16px; }}
    table {{ border-collapse: collapse; width: 100%; min-width: 900px; }}
    th, td {{ border-bottom: 1px solid var(--border); padding: 10px 8px; text-align: left; vertical-align: top; }}
    th {{ background: var(--th); position: sticky; top: 0; }}
    th a:hover {{ text-decoration: underline; }}
    a {{ color: inherit; }}
    .muted {{ color:var(--muted2); font-size: 12px; margin-top: 2px; }}
    .num {{ text-align: right; font-variant-numeric: tabular-nums; }}
    code {{ background:var(--code); padding: 2px 6px; border-radius: 6px; }}
    .pill {{ display:inline-block; padding: 2px 8px; border-radius: 999px; font-size: 12px; }}
    .pill.online {{ background:#dcfce7; color:#166534; }}
    .pill.offline {{ background:#fee2e2; color:#991b1b; }}
    :root[data-theme="dark"] .pill.online {{ background:#14532d; color:#bbf7d0; }}
    :root[data-theme="dark"] .pill.offline {{ background:#7f1d1d; color:#fecaca; }}
    .wrap {{ overflow-x:auto; }}
    .toolbar {{ display:flex; justify-content:flex-end; margin-bottom: 10px; }}
    .theme-btn {{ border:1px solid var(--border); background:var(--btn); color:var(--text); border-radius:10px; padding:6px 10px; cursor:pointer; font-weight:600; }}
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


@router.get("/user-presence.html", response_class=HTMLResponse)
async def user_presence_html(
    username: str = Query(..., min_length=1, max_length=128),
    exact: bool = True,
    live_scan: bool = False,
    max_hosts: int = Query(120, ge=1, le=500),
    db: Session = Depends(get_db),
    user=Depends(require_ui_user),
):
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

    u = (username or "").strip()
    hosts = db.execute(select(Host).order_by(Host.hostname.asc(), Host.agent_id.asc()).limit(max_hosts)).scalars().all()
    visible_hosts = [h for h in hosts if is_host_visible_to_user(db, user, h)]

    rows: list[dict] = []
    skipped_offline = 0
    failed_hosts = 0

    async def query_host_users(agent_id: str) -> dict:
        with transaction(db):
            created = create_job_with_runs(
                db=db,
                job_type="query-users",
                payload={},
                agent_ids=[agent_id],
                commit=False,
            )
        await push_job_to_agents(
            agent_ids=[agent_id],
            job_payload_builder=lambda aid: {"job_id": created.job_key, "type": "query-users"},
        )
        res = await wait_for_job_run(job_id=created.job.id, agent_id=agent_id, timeout_s=10, poll_interval_s=0.25)
        if not res.run:
            raise TimeoutError("query-users timeout")
        if res.run.status == "failed":
            raise RuntimeError(res.run.error or res.run.stderr or "query-users failed")
        return loads_or(res.run.stdout, {}) if getattr(res.run, "stdout", None) else {}

    for h in visible_hosts:
        if not live_scan:
            break
        if not is_host_online(h):
            skipped_offline += 1
            continue
        try:
            data = await query_host_users(h.agent_id)
            users = data.get("users") or []

            # Refresh cached host_users snapshot for this host (fast reports next time).
            with transaction(db):
                db.execute(delete(HostUser).where(HostUser.host_id == h.id))
                for item in users:
                    uname = str(item.get("username") or "").strip()
                    if not uname:
                        continue
                    db.add(
                        HostUser(
                            host_id=h.id,
                            username=uname,
                            uid=(int(item.get("uid")) if str(item.get("uid") or "").isdigit() else None),
                            gid=(int(item.get("gid")) if str(item.get("gid") or "").isdigit() else None),
                            home=(item.get("home") or "")[:512],
                            shell=(item.get("shell") or "")[:128],
                            has_sudo=bool(item.get("has_sudo", False)),
                            is_locked=bool(item.get("is_locked", False)),
                        )
                    )

            for item in users:
                uname = str(item.get("username") or "").strip()
                if not uname:
                    continue
                if exact and uname.lower() != u.lower():
                    continue
                if (not exact) and (u.lower() not in uname.lower()):
                    continue
                rows.append(
                    {
                        "host": h,
                        "username": uname,
                        "shell": item.get("shell") or "",
                        "home": item.get("home") or "",
                        "has_sudo": bool(item.get("has_sudo", False)),
                        "is_locked": bool(item.get("is_locked", False)),
                    }
                )
        except Exception:
            failed_hosts += 1

    # Fallback to cached table if no rows from live scan.
    if not rows:
        if exact:
            stmt = (
                select(HostUser, Host)
                .join(Host, Host.id == HostUser.host_id)
                .where(func.lower(HostUser.username) == u.lower())
                .order_by(Host.hostname.asc(), Host.agent_id.asc())
                .limit(5000)
            )
        else:
            stmt = (
                select(HostUser, Host)
                .join(Host, Host.id == HostUser.host_id)
                .where(func.lower(HostUser.username).like(f"%{u.lower()}%"))
                .order_by(Host.hostname.asc(), Host.agent_id.asc())
                .limit(5000)
            )
        for hu, h in db.execute(stmt).all():
            if not is_host_visible_to_user(db, user, h):
                continue
            rows.append(
                {
                    "host": h,
                    "username": hu.username,
                    "shell": hu.shell or "",
                    "home": hu.home or "",
                    "has_sudo": bool(getattr(hu, "has_sudo", False)),
                    "is_locked": bool(getattr(hu, "is_locked", False)),
                }
            )

    html_rows: list[str] = []
    for r in rows:
        h = r["host"]
        host = esc(h.hostname or h.agent_id or "")
        agent_id = esc(h.agent_id or "")
        ip = esc(h.ip_address or "")
        os_name = esc(((h.os_id or "") + " " + (h.os_version or "")).strip() or "-")
        last_seen = esc(h.last_seen.isoformat() if getattr(h, "last_seen", None) else "")
        shell = esc(r.get("shell") or "")
        home = esc(r.get("home") or "")
        sudo = "yes" if bool(r.get("has_sudo", False)) else "no"
        locked = "yes" if bool(r.get("is_locked", False)) else "no"

        html_rows.append(
            f"<tr>"
            f"<td><b>{host}</b><div class='muted'>{agent_id}{(' • ' + ip) if ip else ''}</div></td>"
            f"<td><code>{esc(r.get('username') or '')}</code></td>"
            f"<td>{os_name}</td>"
            f"<td><code>{shell or '-'}</code><div class='muted'>{home or '-'}</div></td>"
            f"<td>{sudo}</td>"
            f"<td>{locked}</td>"
            f"<td class='muted'>{last_seen}</td>"
            f"</tr>"
        )

    body = "\n".join(html_rows) if html_rows else "<tr><td colspan='7' class='muted'>No matching accounts found on scanned/visible hosts</td></tr>"

    return HTMLResponse(
        content=f"""<!doctype html>
<html>
<head>
  <meta charset='utf-8' />
  <title>Fleet Report - User Presence</title>
  <script src='/assets/fleet-theme-bootstrap.js'></script>
  <style>
    :root {{ --bg:#ffffff; --text:#0f172a; --muted:#475569; --muted2:#64748b; --border:#e2e8f0; --th:#f8fafc; --code:#f1f5f9; --btn:#ffffff; }}
    :root[data-theme="dark"] {{ --bg:#0b1220; --text:#e2e8f0; --muted:#cbd5e1; --muted2:#94a3b8; --border:#334155; --th:#111827; --code:#0f172a; --btn:#111827; }}
    body {{ font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Ubuntu, Cantarell, Noto Sans, Arial; padding: 24px; color:var(--text); background:var(--bg); }}
    h1 {{ margin: 0 0 6px 0; }}
    .meta {{ color:var(--muted); margin-bottom: 16px; }}
    table {{ border-collapse: collapse; width: 100%; min-width: 920px; }}
    th, td {{ border-bottom: 1px solid var(--border); padding: 10px 8px; text-align: left; vertical-align: top; }}
    th {{ background: var(--th); position: sticky; top: 0; }}
    .muted {{ color:var(--muted2); font-size: 12px; margin-top: 2px; }}
    code {{ background:var(--code); padding: 2px 6px; border-radius: 6px; }}
    .wrap {{ overflow-x:auto; }}
    .toolbar {{ display:flex; justify-content:flex-end; margin-bottom: 10px; }}
    .theme-btn {{ border:1px solid var(--border); background:var(--btn); color:var(--text); border-radius:10px; padding:6px 10px; cursor:pointer; font-weight:600; }}
  </style>
</head>
<body>
  <h1>User Presence Report</h1>
  <div class='meta'>Generated: {esc(ts)} UTC • username={esc(u)} • exact={esc(str(exact))} • rows={len(rows)} • scanned_hosts={len(visible_hosts)} • offline_skipped={skipped_offline} • failed_hosts={failed_hosts}</div>
  <div class='wrap'>
    <table>
      <thead>
        <tr>
          <th>Host</th>
          <th>User</th>
          <th>OS</th>
          <th>Shell / Home</th>
          <th>Sudo</th>
          <th>Locked</th>
          <th>Host last seen</th>
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
