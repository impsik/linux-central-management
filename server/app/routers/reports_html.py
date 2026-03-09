from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Query
from fastapi.responses import HTMLResponse, Response
from io import BytesIO

from openpyxl import Workbook
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
            f"<td><b>{host}</b><div class='report-muted'>{agent_id}{(' • ' + ip) if ip else ''}</div></td>"
            f"<td>{os_name}</td>"
            f"<td><code class='report-code'>{kernel}</code></td>"
            f"<td class='num'>{sec}</td>"
            f"<td class='num'>{upd}</td>"
            f"<td><span class='report-pill {online}'>{online}</span></td>"
            f"<td class='report-muted'>{last_seen}</td>"
            f"</tr>"
        )

    body = "\n".join(html_rows) if html_rows else "<tr><td colspan='7' class='report-muted'>No rows</td></tr>"

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
        return f"<a href='{esc(href)}' class='report-sort-link'>{esc(label)}{arrow}</a>"

    filename = f"pending-updates-{now.strftime('%Y%m%d-%H%M%S')}Z.html"

    return HTMLResponse(
        content=f"""<!doctype html>
<html>
<head>
  <meta charset='utf-8' />
  <title>Fleet Report - Pending Updates</title>
  <link rel='stylesheet' href='/assets/fleet-ui.css' />
  <script src='/assets/fleet-theme-bootstrap.js'></script>
</head>
<body class='fleet-report'>
  <h1>Pending Updates Report</h1>
  <div class='report-meta'>Generated: {esc(ts)} UTC • only_pending={esc(str(only_pending))} • online_only={esc(str(online_only))} • sort={esc(sort)} {esc(order)} • rows={len(rows)}</div>
  <div class='report-wrap'>
    <table class='report-table'>
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


@router.get("/hosts-updates.xlsx")
def hosts_updates_xlsx(
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

    rows = data.get("items") or []

    wb = Workbook()
    ws = wb.active
    ws.title = "Hosts Updates"

    ws.append(["Host", "Agent ID", "IP Address", "OS", "Kernel", "Security Updates", "All Updates", "Online", "Last Seen"])

    for r in rows:
      last_seen = r.get("last_seen")
      # openpyxl/Excel does not support timezone-aware datetimes reliably.
      # Normalize to readable UTC-ish string for portability.
      if isinstance(last_seen, datetime):
          last_seen = last_seen.isoformat()
      elif last_seen is None:
          last_seen = ""
      else:
          last_seen = str(last_seen)

      ws.append([
          r.get("hostname") or r.get("agent_id") or "",
          r.get("agent_id") or "",
          r.get("ip_address") or "",
          ((r.get("os_id") or "") + " " + (r.get("os_version") or "")).strip(),
          r.get("kernel") or "",
          int(r.get("security_updates") or 0),
          int(r.get("updates") or 0),
          "online" if r.get("is_online") else "offline",
          last_seen,
      ])

    # Simple width tuning for readability in Excel.
    widths = {"A": 28, "B": 28, "C": 18, "D": 24, "E": 22, "F": 16, "G": 14, "H": 10, "I": 28}
    for col, width in widths.items():
        ws.column_dimensions[col].width = width

    stream = BytesIO()
    wb.save(stream)
    stream.seek(0)

    filename = f"hosts-updates-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}Z.xlsx"
    return Response(
        content=stream.getvalue(),
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Cache-Control": "no-store",
        },
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
            f"<td><b>{host}</b><div class='report-muted'>{agent_id}{(' • ' + ip) if ip else ''}</div></td>"
            f"<td><code class='report-code'>{esc(r.get('username') or '')}</code></td>"
            f"<td>{os_name}</td>"
            f"<td><code class='report-code'>{shell or '-'}</code><div class='report-muted'>{home or '-'}</div></td>"
            f"<td>{sudo}</td>"
            f"<td>{locked}</td>"
            f"<td class='report-muted'>{last_seen}</td>"
            f"</tr>"
        )

    body = "\n".join(html_rows) if html_rows else "<tr><td colspan='7' class='report-muted'>No matching accounts found on scanned/visible hosts</td></tr>"

    return HTMLResponse(
        content=f"""<!doctype html>
<html>
<head>
  <meta charset='utf-8' />
  <title>Fleet Report - User Presence</title>
  <link rel='stylesheet' href='/assets/fleet-ui.css' />
  <script src='/assets/fleet-theme-bootstrap.js'></script>
</head>
<body class='fleet-report'>
  <h1>User Presence Report</h1>
  <div class='report-meta'>Generated: {esc(ts)} UTC • username={esc(u)} • exact={esc(str(exact))} • rows={len(rows)} • scanned_hosts={len(visible_hosts)} • offline_skipped={skipped_offline} • failed_hosts={failed_hosts}</div>
  <div class='report-wrap'>
    <table class='report-table' style='min-width:920px;'>
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
