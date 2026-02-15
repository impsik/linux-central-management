from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..db import get_db
from ..deps import require_ui_user
from ..models import HighRiskActionRequest, Host, HostPackageUpdate, PatchCampaign, PatchCampaignHost
from ..services.db_utils import transaction
from ..services.high_risk_approval import is_approval_required
from ..services.maintenance import assert_action_allowed_now
from ..services.patching import create_patch_campaign

router = APIRouter(prefix="/patching", tags=["patching"])


@router.get("/dashboard")
def patching_dashboard(
    labels: str | None = None,
    db: Session = Depends(get_db),
):
    """High-level patching posture.

    NOTE: "security" is currently best-effort: we treat all upgradable packages as candidates.
    """

    # Optional label filter in `k=v,k2=v2` form
    label_filter = {}
    if labels:
        for part in labels.split(","):
            part = part.strip()
            if not part:
                continue
            if "=" not in part:
                continue
            k, v = part.split("=", 1)
            label_filter[k.strip()] = v.strip()

    host_q = select(func.count()).select_from(Host)
    if label_filter:
        # naive JSON contains filter (Postgres supports @> nicely; keep generic via python-side filter fallback)
        # We implement Postgres path; for sqlite dev this will likely be ignored.
        try:
            host_q = host_q.where(Host.labels.contains(label_filter))  # type: ignore[attr-defined]
        except Exception:
            pass

    hosts_total = int(db.execute(host_q).scalar_one() or 0)

    updates_q = select(func.count()).select_from(HostPackageUpdate).where(HostPackageUpdate.update_available == True)  # noqa: E712
    if label_filter:
        updates_q = updates_q.join(Host, Host.id == HostPackageUpdate.host_id)
        try:
            updates_q = updates_q.where(Host.labels.contains(label_filter))  # type: ignore[attr-defined]
        except Exception:
            pass

    updates_total = int(db.execute(updates_q).scalar_one() or 0)

    hosts_with_updates_q = (
        select(func.count(func.distinct(HostPackageUpdate.host_id)))
        .select_from(HostPackageUpdate)
        .where(HostPackageUpdate.update_available == True)  # noqa: E712
    )
    if label_filter:
        hosts_with_updates_q = hosts_with_updates_q.join(Host, Host.id == HostPackageUpdate.host_id)
        try:
            hosts_with_updates_q = hosts_with_updates_q.where(Host.labels.contains(label_filter))  # type: ignore[attr-defined]
        except Exception:
            pass

    hosts_with_updates = int(db.execute(hosts_with_updates_q).scalar_one() or 0)

    return {
        "ts": datetime.now(timezone.utc).isoformat(),
        "hosts": {"total": hosts_total, "with_updates": hosts_with_updates},
        "updates": {"total": updates_total},
        "notes": [
            "Security classification not implemented yet; dashboard counts all upgradable packages.",
        ],
    }


@router.post("/campaigns/security-updates")
def create_security_updates_campaign(
    payload: dict,
    db: Session = Depends(get_db),
    user=Depends(require_ui_user),
):
    """Create a patch campaign.

    Expected payload (MVP):
    {
      "labels": {"env":"prod"},
      "agent_ids": ["srv-001"],
      "rings": [
         {"name":"canary", "agent_ids":[...]},
         {"name":"rest", "agent_ids":[...]}
      ],
      "window_start": "2026-02-05T16:00:00Z",
      "window_end": "2026-02-05T20:00:00Z",
      "concurrency": 5,
      "reboot_if_needed": true,
      "include_kernel": false
    }
    """

    try:
        assert_action_allowed_now("security-campaign")
    except PermissionError as e:
        raise HTTPException(403, str(e))

    window_start = payload.get("window_start")
    window_end = payload.get("window_end")
    if not window_start or not window_end:
        raise HTTPException(400, "window_start and window_end are required")

    try:
        ws = datetime.fromisoformat(str(window_start).replace("Z", "+00:00"))
        we = datetime.fromisoformat(str(window_end).replace("Z", "+00:00"))
    except Exception:
        raise HTTPException(400, "window_start/window_end must be ISO timestamps")

    if we <= ws:
        raise HTTPException(400, "window_end must be after window_start")

    concurrency = int(payload.get("concurrency") or 5)
    if concurrency < 1:
        concurrency = 1
    if concurrency > 100:
        concurrency = 100

    rings = payload.get("rings")
    labels = payload.get("labels")
    agent_ids = payload.get("agent_ids")

    if is_approval_required("security-campaign"):
        with transaction(db):
            req = HighRiskActionRequest(
                user_id=user.id,
                action="security-campaign",
                payload={
                    "labels": labels,
                    "agent_ids": agent_ids,
                    "rings": rings,
                    "window_start": ws.isoformat(),
                    "window_end": we.isoformat(),
                    "concurrency": concurrency,
                    "reboot_if_needed": bool(payload.get("reboot_if_needed") or False),
                    "include_kernel": bool(payload.get("include_kernel") or False),
                },
                status="pending",
            )
            db.add(req)
        return {"approval_required": True, "request_id": str(req.id), "action": "security-campaign", "status": "pending"}

    with transaction(db):
        c = create_patch_campaign(
            db=db,
            created_by=str(payload.get("created_by") or "ui"),
            kind="security-updates",
            labels=labels,
            agent_ids=agent_ids,
            rings=rings,
            window_start=ws,
            window_end=we,
            concurrency=concurrency,
            reboot_if_needed=bool(payload.get("reboot_if_needed") or False),
            include_kernel=bool(payload.get("include_kernel") or False),
        )

    return {"campaign_id": c.campaign_key, "status": c.status}


@router.get("/campaigns/{campaign_id}")
def get_campaign(campaign_id: str, db: Session = Depends(get_db)):
    c = db.execute(select(PatchCampaign).where(PatchCampaign.campaign_key == campaign_id)).scalar_one_or_none()
    if not c:
        raise HTTPException(404, "unknown campaign")

    hosts = (
        db.execute(
            select(PatchCampaignHost)
            .where(PatchCampaignHost.campaign_id == c.id)
            .order_by(PatchCampaignHost.ring.asc(), PatchCampaignHost.agent_id.asc())
        )
        .scalars()
        .all()
    )

    return {
        "campaign_id": c.campaign_key,
        "kind": c.kind,
        "selector": c.selector,
        "rings": c.rings,
        "window_start": c.window_start,
        "window_end": c.window_end,
        "concurrency": c.concurrency,
        "reboot_if_needed": c.reboot_if_needed,
        "include_kernel": c.include_kernel,
        "status": c.status,
        "created_at": c.created_at,
        "started_at": c.started_at,
        "finished_at": c.finished_at,
        "hosts": [
            {
                "agent_id": h.agent_id,
                "ring": h.ring,
                "status": h.status,
                "job_key_upgrade": h.job_key_upgrade,
                "job_key_reboot_check": h.job_key_reboot_check,
                "job_key_reboot": h.job_key_reboot,
                "reboot_required": h.reboot_required,
                "error": h.error,
                "started_at": h.started_at,
                "finished_at": h.finished_at,
            }
            for h in hosts
        ],
    }
