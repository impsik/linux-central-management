from __future__ import annotations

import asyncio
import json
import secrets
from contextlib import suppress
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import and_, func, select
from sqlalchemy.orm import Session

from ..db import SessionLocal
from ..dispatcher import dispatcher
from ..models import (
    AuditLog,
    Host,
    HostPackageUpdate,
    Job,
    JobRun,
    PatchCampaign,
    PatchCampaignHost,
)
from ..services.jobs import create_job_with_runs, push_job_to_agents
from ..services.targets import resolve_agent_ids


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _new_key(prefix: str) -> str:
    return f"{prefix}_{secrets.token_hex(12)}"


def _audit(db: Session, *, actor: str | None, action: str, entity_type: str, entity_key: str | None, detail: dict) -> None:
    db.add(
        AuditLog(
            actor=actor,
            action=action,
            entity_type=entity_type,
            entity_key=entity_key,
            detail=detail or {},
        )
    )


def create_patch_campaign(
    *,
    db: Session,
    created_by: str | None,
    kind: str,
    labels: dict | None,
    agent_ids: list[str] | None,
    rings: list[dict] | None,
    window_start: datetime,
    window_end: datetime,
    concurrency: int,
    reboot_if_needed: bool,
    include_kernel: bool = False,
) -> PatchCampaign:
    # Resolve targets
    targets = resolve_agent_ids(db, agent_ids, labels)
    if rings:
        # If rings are provided, only include those agents.
        ring_agent_ids: list[str] = []
        for r in rings:
            if isinstance(r, dict):
                ring_agent_ids.extend([str(x) for x in (r.get("agent_ids") or [])])
        targets = [t for t in targets if t in set(ring_agent_ids)]

    if not targets:
        raise ValueError("No targets resolved")

    # Normalize rings: if none provided, create a single ring
    norm_rings: list[dict[str, Any]] = []
    if rings:
        for idx, r in enumerate(rings):
            if not isinstance(r, dict):
                continue
            aids = [str(x) for x in (r.get("agent_ids") or []) if str(x).strip()]
            if not aids:
                continue
            norm_rings.append({"name": str(r.get("name") or f"ring-{idx}"), "agent_ids": aids})
    else:
        norm_rings = [{"name": "all", "agent_ids": list(targets)}]

    campaign_key = _new_key("pc")
    c = PatchCampaign(
        campaign_key=campaign_key,
        created_by=created_by,
        kind=kind,
        selector={"labels": labels or None, "agent_ids": agent_ids or None},
        rings=norm_rings,
        window_start=window_start,
        window_end=window_end,
        concurrency=concurrency,
        reboot_if_needed=reboot_if_needed,
        include_kernel=bool(include_kernel),
        status="scheduled",
    )
    db.add(c)
    db.flush()

    agent_to_ring: dict[str, int] = {}
    for ring_idx, r in enumerate(norm_rings):
        for aid in r.get("agent_ids") or []:
            agent_to_ring[str(aid)] = ring_idx

    for aid in targets:
        db.add(PatchCampaignHost(campaign_id=c.id, agent_id=aid, ring=int(agent_to_ring.get(aid, 0))))

    _audit(
        db,
        actor=created_by,
        action="patch_campaign.create",
        entity_type="patch_campaign",
        entity_key=campaign_key,
        detail={
            "kind": kind,
            "targets": list(targets),
            "rings": norm_rings,
            "window_start": window_start.isoformat(),
            "window_end": window_end.isoformat(),
            "concurrency": concurrency,
            "reboot_if_needed": reboot_if_needed,
            "note": "Security classification not implemented yet; campaign applies all upgradable packages.",
        },
    )

    return c


async def campaign_loop(stop_event: asyncio.Event, *, tick_s: float = 2.0) -> None:
    """Background loop that dispatches patch campaigns within their maintenance windows."""

    while not stop_event.is_set():
        try:
            await _run_campaign_tick()
        except Exception:
            # best-effort background loop; never crash the app
            pass
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=tick_s)
        except asyncio.TimeoutError:
            continue


async def _run_campaign_tick() -> None:
    db = SessionLocal()
    try:
        now = _now()

        # Active campaigns = scheduled/running within their window
        campaigns = (
            db.execute(
                select(PatchCampaign)
                .where(
                    PatchCampaign.status.in_(["scheduled", "running"]),
                    PatchCampaign.window_start <= now,
                    PatchCampaign.window_end >= now,
                )
                .order_by(PatchCampaign.created_at.asc())
                .limit(20)
            )
            .scalars()
            .all()
        )

        for c in campaigns:
            await _advance_campaign(db, c)

        db.commit()
    finally:
        db.close()


async def _advance_campaign(db: Session, c: PatchCampaign) -> None:
    now = _now()

    if c.status == "scheduled":
        c.status = "running"
        c.started_at = c.started_at or now

    # Compute how many hosts are currently running
    running = int(
        db.execute(
            select(func.count())
            .select_from(PatchCampaignHost)
            .where(PatchCampaignHost.campaign_id == c.id, PatchCampaignHost.status == "running")
        ).scalar_one()
        or 0
    )

    # Fill free slots
    free = max(0, int(c.concurrency or 1) - running)
    if free > 0:
        queued_hosts = (
            db.execute(
                select(PatchCampaignHost)
                .where(PatchCampaignHost.campaign_id == c.id, PatchCampaignHost.status == "queued")
                .order_by(PatchCampaignHost.ring.asc(), PatchCampaignHost.agent_id.asc())
                .limit(free)
            )
            .scalars()
            .all()
        )
        for h in queued_hosts:
            await _dispatch_host_upgrade(db, c, h)

    # Reconcile running hosts by reading their job statuses
    running_hosts = (
        db.execute(
            select(PatchCampaignHost)
            .where(PatchCampaignHost.campaign_id == c.id, PatchCampaignHost.status == "running")
            .order_by(PatchCampaignHost.ring.asc(), PatchCampaignHost.agent_id.asc())
        )
        .scalars()
        .all()
    )
    for h in running_hosts:
        await _reconcile_host(db, c, h)

    # Finish campaign if everything is done
    remaining = int(
        db.execute(
            select(func.count())
            .select_from(PatchCampaignHost)
            .where(PatchCampaignHost.campaign_id == c.id, PatchCampaignHost.status.in_(["queued", "running"]))
        ).scalar_one()
        or 0
    )
    if remaining == 0:
        failed = int(
            db.execute(
                select(func.count())
                .select_from(PatchCampaignHost)
                .where(PatchCampaignHost.campaign_id == c.id, PatchCampaignHost.status == "failed")
            ).scalar_one()
            or 0
        )
        c.status = "failed" if failed > 0 else "success"
        c.finished_at = c.finished_at or now


async def _dispatch_host_upgrade(db: Session, c: PatchCampaign, h: PatchCampaignHost) -> None:
    now = _now()

    # Resolve host row
    host = db.execute(select(Host).where(Host.agent_id == h.agent_id)).scalar_one_or_none()
    if not host:
        h.status = "failed"
        h.error = "unknown agent_id"
        h.finished_at = now
        return

    # Compute packages to upgrade from cached upgradable snapshot
    q = select(HostPackageUpdate.name, HostPackageUpdate.candidate_version).where(
        HostPackageUpdate.host_id == host.id,
        HostPackageUpdate.update_available == True,  # noqa: E712
    )

    # If this is a security-updates campaign, filter to security-marked updates only.
    if (c.kind or "") == "security-updates":
        q = q.where(HostPackageUpdate.is_security == True)  # noqa: E712

    rows = db.execute(q.order_by(HostPackageUpdate.name.asc())).all()

    packages: list[str] = []
    for name, cand_ver in rows:
        n = str(name or "").strip()
        v = str(cand_ver or "").strip()
        if not n:
            continue

        # If include_kernel=true, we allow kernel/meta packages but pin versions when known.
        if bool(getattr(c, "include_kernel", False)):
            if n.startswith("linux-") and v:
                packages.append(f"{n}={v}")
            else:
                packages.append(n)
        else:
            packages.append(n)

    # MVP safety: kernel/meta package upgrades frequently require repo consistency and reboots.
    # For security-only campaigns, exclude kernel/meta packages by default.
    if (c.kind or "") == "security-updates" and not bool(getattr(c, "include_kernel", False)):
        excludes_prefix = (
            "linux-headers-",
            "linux-image-",
            "linux-modules-",
        )
        excludes_exact = {
            "linux-headers-generic",
            "linux-image-generic",
            "linux-generic",
            "linux-virtual",
            "linux-headers-virtual",
            "linux-image-virtual",
        }

        filtered: list[str] = []
        for name in packages:
            n = name.strip()
            if not n:
                continue
            if n in excludes_exact:
                continue
            if any(n.startswith(pfx) for pfx in excludes_prefix):
                continue
            if n.endswith("-generic") and n.startswith("linux-"):
                continue
            filtered.append(n)

        packages = filtered

    if not packages:
        h.status = "skipped"
        h.finished_at = now
        return

    job_type = "pkg-upgrade"
    if bool(getattr(c, "include_kernel", False)):
        # Use apt-get install (optionally pinned versions) to handle kernel/meta upgrades.
        job_type = "pkg-install"

    job = create_job_with_runs(
        db=db,
        job_type=job_type,
        payload={"packages": packages, "campaign_id": c.campaign_key},
        agent_ids=[h.agent_id],
        commit=False,
        created_by=c.created_by,
    )
    h.job_key_upgrade = job.job_key
    h.status = "running"
    h.started_at = h.started_at or now

    _audit(
        db,
        actor=c.created_by,
        action="patch_campaign.dispatch_upgrade",
        entity_type="patch_campaign",
        entity_key=c.campaign_key,
        detail={"agent_id": h.agent_id, "packages": packages, "job_id": job.job_key},
    )

    # Push to agent immediately
    # NOTE: this is synchronous here; safe because it only enqueues in memory.
    await push_job_to_agents(
        agent_ids=[h.agent_id],
        job_payload_builder=lambda aid: {"job_id": job.job_key, "type": job_type, "packages": packages},
    )


async def _reconcile_host(db: Session, c: PatchCampaign, h: PatchCampaignHost) -> None:
    now = _now()

    if not h.job_key_upgrade:
        # Nothing to do
        h.status = "failed"
        h.error = "missing upgrade job key"
        h.finished_at = now
        return

    job = db.execute(select(Job).where(Job.job_key == h.job_key_upgrade)).scalar_one_or_none()
    if not job:
        return

    run = db.execute(
        select(JobRun).where(and_(JobRun.job_id == job.id, JobRun.agent_id == h.agent_id))
    ).scalar_one_or_none()
    if not run:
        return

    if run.status in ("queued", "running"):
        return

    if run.status == "failed":
        h.status = "failed"
        h.error = run.error or "upgrade failed"
        h.finished_at = now
        _audit(
            db,
            actor=c.created_by,
            action="patch_campaign.host_failed",
            entity_type="patch_campaign",
            entity_key=c.campaign_key,
            detail={"agent_id": h.agent_id, "job_id": h.job_key_upgrade, "error": h.error},
        )
        return

    # Upgrade success
    if not c.reboot_if_needed:
        h.status = "success"
        h.finished_at = now
        return

    # Trigger reboot check job if not done
    if not h.job_key_reboot_check:
        check_job = create_job_with_runs(
            db=db,
            job_type="check-reboot",
            payload={"campaign_id": c.campaign_key},
            agent_ids=[h.agent_id],
            commit=False,
            created_by=c.created_by,
        )
        h.job_key_reboot_check = check_job.job_key

        await push_job_to_agents(
            agent_ids=[h.agent_id],
            job_payload_builder=lambda aid: {"job_id": check_job.job_key, "type": "check-reboot"},
        )
        return

    # Read reboot check result
    check = db.execute(select(Job).where(Job.job_key == h.job_key_reboot_check)).scalar_one_or_none()
    if not check:
        return
    check_run = db.execute(
        select(JobRun).where(and_(JobRun.job_id == check.id, JobRun.agent_id == h.agent_id))
    ).scalar_one_or_none()
    if not check_run or check_run.status in ("queued", "running"):
        return

    reboot_required = False
    if check_run.status == "success" and (check_run.stdout or "").strip():
        with suppress(Exception):
            data = json.loads(check_run.stdout or "{}")
            reboot_required = bool(data.get("reboot_required"))

    h.reboot_required = reboot_required

    if not reboot_required:
        h.status = "success"
        h.finished_at = now
        return

    # Dispatch reboot job if required and not yet dispatched
    if not h.job_key_reboot:
        reboot_job = create_job_with_runs(
            db=db,
            job_type="reboot",
            payload={"campaign_id": c.campaign_key},
            agent_ids=[h.agent_id],
            commit=False,
            created_by=c.created_by,
        )
        h.job_key_reboot = reboot_job.job_key

        await push_job_to_agents(
            agent_ids=[h.agent_id],
            job_payload_builder=lambda aid: {"job_id": reboot_job.job_key, "type": "reboot"},
        )
        return

    reboot = db.execute(select(Job).where(Job.job_key == h.job_key_reboot)).scalar_one_or_none()
    if not reboot:
        return
    reboot_run = db.execute(
        select(JobRun).where(and_(JobRun.job_id == reboot.id, JobRun.agent_id == h.agent_id))
    ).scalar_one_or_none()
    if not reboot_run or reboot_run.status in ("queued", "running"):
        return

    if reboot_run.status == "failed":
        h.status = "failed"
        h.error = reboot_run.error or "reboot failed"
        h.finished_at = now
        return

    # Reboot command was accepted.
    h.status = "success"
    h.finished_at = now
