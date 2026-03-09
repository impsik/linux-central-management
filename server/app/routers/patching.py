from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..db import get_db
from ..deps import require_ui_user
from ..models import HighRiskActionRequest, Host, HostPackageUpdate, PatchCampaign, PatchCampaignHost, CVEDefinition
from ..services.audit import log_event
from ..services.db_utils import transaction
from ..services.high_risk_approval import is_approval_required
from ..services.maintenance import assert_action_allowed_now
from ..services.patching import (
    build_security_wave_plan,
    create_patch_campaign,
    get_rollout_meta,
    get_rollout_summary,
    set_rollout_meta,
)
from ..services.targets import resolve_agent_ids

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
    request: Request,
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
    rollout_controls = payload.get("rollout_controls") if isinstance(payload.get("rollout_controls"), dict) else None

    scoped_targets = resolve_agent_ids(db, agent_ids, labels, user=user)
    if not scoped_targets:
        raise HTTPException(400, "No targets resolved within your scope")

    if is_approval_required("security-campaign"):
        with transaction(db):
            req = HighRiskActionRequest(
                user_id=user.id,
                action="security-campaign",
                payload={
                    "labels": labels,
                    "agent_ids": scoped_targets,
                    "rings": rings,
                    "window_start": ws.isoformat(),
                    "window_end": we.isoformat(),
                    "concurrency": concurrency,
                    "reboot_if_needed": bool(payload.get("reboot_if_needed") or False),
                    "include_kernel": bool(payload.get("include_kernel") or False),
                    "rollout_controls": rollout_controls,
                },
                status="pending",
            )
            db.add(req)
            db.flush()
            log_event(
                db,
                action="high_risk.request.created",
                actor=user,
                request=request,
                target_type="high_risk_action_request",
                target_id=str(req.id),
                target_name="security-campaign",
                meta={
                    "request_id": str(req.id),
                    "action": "security-campaign",
                    "agent_count": len(scoped_targets or []),
                    "label_count": len((labels or {}).keys()) if isinstance(labels, dict) else 0,
                },
            )
        return {"approval_required": True, "request_id": str(req.id), "action": "security-campaign", "status": "pending"}

    with transaction(db):
        c = create_patch_campaign(
            db=db,
            created_by=str(payload.get("created_by") or "ui"),
            kind="security-updates",
            labels=labels,
            agent_ids=scoped_targets,
            rings=rings,
            window_start=ws,
            window_end=we,
            concurrency=concurrency,
            reboot_if_needed=bool(payload.get("reboot_if_needed") or False),
            include_kernel=bool(payload.get("include_kernel") or False),
            rollout_controls=rollout_controls,
        )

    return {"campaign_id": c.campaign_key, "status": c.status}


@router.post("/campaigns/security-updates/preview")
def preview_security_updates_campaign_wave_plan(
    payload: dict,
    db: Session = Depends(get_db),
    user=Depends(require_ui_user),
):
    labels = payload.get("labels")
    agent_ids = payload.get("agent_ids")
    wave_plan = payload.get("wave_plan")
    if wave_plan is not None and not isinstance(wave_plan, dict):
        raise HTTPException(400, "wave_plan must be an object")

    try:
        plan = build_security_wave_plan(
            db=db,
            labels=labels,
            agent_ids=agent_ids,
            wave_plan=wave_plan,
            user=user,
        )
    except ValueError as e:
        raise HTTPException(400, str(e))

    return plan


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
        "rollout": get_rollout_meta(c),
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

@router.get("/campaigns/{campaign_id}/rollout")
def get_campaign_rollout(campaign_id: str, db: Session = Depends(get_db), _=Depends(require_ui_user)):
    c = db.execute(select(PatchCampaign).where(PatchCampaign.campaign_key == campaign_id)).scalar_one_or_none()
    if not c:
        raise HTTPException(404, "unknown campaign")
    return get_rollout_summary(db, c)


@router.post("/campaigns/{campaign_id}/pause")
def pause_campaign_rollout(campaign_id: str, request: Request, db: Session = Depends(get_db), user=Depends(require_ui_user)):
    c = db.execute(select(PatchCampaign).where(PatchCampaign.campaign_key == campaign_id)).scalar_one_or_none()
    if not c:
        raise HTTPException(404, "unknown campaign")
    if c.status not in ("scheduled", "running"):
        raise HTTPException(409, f"campaign not active (status={c.status})")

    meta = get_rollout_meta(c)
    meta["paused"] = True
    meta["pause_reason"] = str((request.query_params.get("reason") or "Paused by operator")).strip()[:500]
    meta["paused_at"] = datetime.now(timezone.utc).isoformat()
    meta["paused_by"] = getattr(user, "username", None)
    meta["manual_resume_required"] = False
    set_rollout_meta(c, meta)

    log_event(
        db,
        action="patch_campaign.paused",
        actor=user,
        request=request,
        target_type="patch_campaign",
        target_id=str(c.id),
        target_name=c.campaign_key,
        meta={"campaign_id": c.campaign_key, "reason": meta.get("pause_reason")},
    )
    db.commit()
    return get_rollout_summary(db, c)


@router.post("/campaigns/{campaign_id}/resume")
def resume_campaign_rollout(campaign_id: str, request: Request, db: Session = Depends(get_db), user=Depends(require_ui_user)):
    c = db.execute(select(PatchCampaign).where(PatchCampaign.campaign_key == campaign_id)).scalar_one_or_none()
    if not c:
        raise HTTPException(404, "unknown campaign")
    if c.status not in ("scheduled", "running"):
        raise HTTPException(409, f"campaign not active (status={c.status})")

    meta = get_rollout_meta(c)
    meta["paused"] = False
    meta["pause_reason"] = None
    meta["paused_at"] = None
    meta["manual_resume_required"] = False
    meta["paused_by"] = getattr(user, "username", None)
    set_rollout_meta(c, meta)

    log_event(
        db,
        action="patch_campaign.resumed",
        actor=user,
        request=request,
        target_type="patch_campaign",
        target_id=str(c.id),
        target_name=c.campaign_key,
        meta={"campaign_id": c.campaign_key},
    )
    db.commit()
    return get_rollout_summary(db, c)


@router.post("/campaigns/{campaign_id}/approve-next")
def approve_next_wave(campaign_id: str, request: Request, db: Session = Depends(get_db), user=Depends(require_ui_user)):
    c = db.execute(select(PatchCampaign).where(PatchCampaign.campaign_key == campaign_id)).scalar_one_or_none()
    if not c:
        raise HTTPException(404, "unknown campaign")

    meta = get_rollout_meta(c)
    if not bool(meta.get("progressive")):
        raise HTTPException(409, "campaign is not in progressive rollout mode")

    max_ring = max(0, len(c.rings or []) - 1)
    approved = int(meta.get("approved_through_ring") or 0)
    if approved >= max_ring:
        raise HTTPException(409, "all rings already approved")

    meta["approved_through_ring"] = approved + 1
    set_rollout_meta(c, meta)

    log_event(
        db,
        action="patch_campaign.approve_next_wave",
        actor=user,
        request=request,
        target_type="patch_campaign",
        target_id=str(c.id),
        target_name=c.campaign_key,
        meta={"campaign_id": c.campaign_key, "approved_through_ring": approved + 1},
    )
    db.commit()
    return get_rollout_summary(db, c)


@router.get("/cve/{cve_id}")
def get_cve(cve_id: str, distro_codename: str | None = None, db: Session = Depends(get_db)):
    """Check CVE status locally (no internet leak)."""
    cve_id = cve_id.upper()
    cve = db.execute(select(CVEDefinition).where(CVEDefinition.cve_id == cve_id)).scalar_one_or_none()

    if not cve:
        return {"cve": cve_id, "found": False}

    data = cve.definition_data or {}

    if not distro_codename:
        return {"cve": cve_id, "found": True, "data": data}

    distro_data = data.get(distro_codename)
    if not distro_data:
        return {"cve": cve_id, "found": True, "distro_found": False, "data": None}

    return {"cve": cve_id, "found": True, "distro_found": True, "data": distro_data}
