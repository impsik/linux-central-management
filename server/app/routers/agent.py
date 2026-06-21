from __future__ import annotations

from datetime import datetime, timedelta, timezone
import ipaddress
import secrets

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from ..config import settings
from ..db import get_db
from ..dispatcher import dispatcher
from ..models import Host, HostCVEStatus, HostLoadMetric, HostMetricsSnapshot, HostPackage, HostPackageUpdate, Job, JobRun
from ..schemas import AgentRegister, JobEvent, PackageUpdatesInventory, PackagesInventory
from ..services.agents import get_client_ip
from ..services.agent_auth import hash_agent_token, require_agent_token_dep
from ..services.audit import log_event
from ..services.db_utils import transaction
from ..services.jobs import create_job_with_runs

router = APIRouter(prefix="/agent", tags=["agent"], dependencies=[Depends(require_agent_token_dep)])


def _preferred_reported_ip(ip_addresses: list[str] | None) -> str | None:
    for raw in ip_addresses or []:
        try:
            ip = ipaddress.ip_address(str(raw).strip())
        except ValueError:
            continue
        if ip.version != 4 or ip.is_loopback or ip.is_link_local or ip.is_unspecified:
            continue
        return str(ip)
    return None


def _ensure_job_run_nonce(run: JobRun) -> str:
    nonce = (getattr(run, "job_nonce", None) or "").strip()
    if not nonce:
        nonce = secrets.token_urlsafe(32)
        run.job_nonce = nonce
    return nonce


def _with_job_nonce(payload: dict, run: JobRun) -> dict:
    out = dict(payload)
    out["job_nonce"] = _ensure_job_run_nonce(run)
    return out


def _audit_unknown_agent(db: Session, request: Request, agent_id: str, action: str) -> None:
    try:
        log_event(
            db,
            action="agent.unknown",
            actor=None,
            request=request,
            target_type="agent",
            target_id=agent_id,
            meta={"agent_action": action},
        )
        db.commit()
    except Exception:
        try:
            db.rollback()
        except Exception:
            pass


def _ensure_agent_identity(request: Request, agent_id: str) -> None:
    auth_kind = getattr(request.state, "agent_auth_kind", "shared")
    auth_agent_id = getattr(request.state, "agent_auth_agent_id", None)
    if auth_kind == "per_agent" and auth_agent_id != agent_id:
        raise HTTPException(403, "agent token does not match agent_id")


def _issue_agent_token(host: Host) -> str:
    token = secrets.token_urlsafe(32)
    host.agent_token_hash = hash_agent_token(token)
    return token


@router.post("/register")
def agent_register(payload: AgentRegister, request: Request, db: Session = Depends(get_db)):
    _ensure_agent_identity(request, payload.agent_id)
    host = db.execute(select(Host).where(Host.agent_id == payload.agent_id)).scalar_one_or_none()
    now = datetime.now(timezone.utc)

    client_ip = get_client_ip(request)
    reported_ip = _preferred_reported_ip(payload.ip_addresses)
    host_ip = reported_ip or client_ip

    if not host:
        host_data = {
            "agent_id": payload.agent_id,
            "hostname": payload.hostname,
            "fqdn": payload.fqdn,
            "os_id": payload.os_id,
            "os_version": payload.os_version,
            "kernel": payload.kernel,
            "agent_version": payload.agent_version,
            "labels": payload.labels or {},
            "last_seen": now,
        }
        if host_ip and hasattr(Host, "ip_address"):
            host_data["ip_address"] = host_ip
        host = Host(**host_data)
        db.add(host)
    else:
        if (
            getattr(request.state, "agent_auth_kind", "shared") == "shared"
            and (getattr(host, "agent_token_hash", None) or "").strip()
        ):
            raise HTTPException(403, "existing agent requires per-agent token")

        host.hostname = payload.hostname
        host.fqdn = payload.fqdn
        if host_ip and hasattr(host, "ip_address"):
            host.ip_address = host_ip
        host.os_id = payload.os_id
        host.os_version = payload.os_version
        host.kernel = payload.kernel
        if payload.agent_version:
            host.agent_version = payload.agent_version

        # Preserve UI-managed metadata (e.g. role/env) when agent re-registers without labels.
        existing_labels = dict(host.labels or {}) if isinstance(host.labels, dict) else {}
        incoming_labels = payload.labels or {}
        if incoming_labels:
            merged_labels = dict(existing_labels)
            merged_labels.update(incoming_labels)
            host.labels = merged_labels
        else:
            host.labels = existing_labels

        host.last_seen = now

    agent_token = None
    if getattr(request.state, "agent_auth_kind", "shared") == "shared":
        agent_token = _issue_agent_token(host)

    db.commit()
    body = {"ok": True}
    if agent_token:
        body["agent_token"] = agent_token
    return body


@router.post("/heartbeat")
def agent_heartbeat(
    request: Request,
    agent_id: str,
    agent_version: str | None = None,
    db: Session = Depends(get_db),
):
    _ensure_agent_identity(request, agent_id)
    host = db.execute(select(Host).where(Host.agent_id == agent_id)).scalar_one_or_none()
    if not host:
        _audit_unknown_agent(db, request, agent_id, "heartbeat")
        raise HTTPException(404, "unknown agent")

    client_ip = get_client_ip(request)
    if client_ip and hasattr(host, "ip_address") and not host.ip_address:
        host.ip_address = client_ip

    if agent_version:
        host.agent_version = agent_version

    host.last_seen = datetime.now(timezone.utc)
    db.commit()
    return {"ok": True}


@router.post("/inventory/packages")
def agent_inventory_packages(payload: PackagesInventory, request: Request, db: Session = Depends(get_db)):
    _ensure_agent_identity(request, payload.agent_id)
    host = db.execute(select(Host).where(Host.agent_id == payload.agent_id)).scalar_one_or_none()
    if not host:
        _audit_unknown_agent(db, request, payload.agent_id, "inventory_packages")
        raise HTTPException(404, "unknown agent")

    collected_at = datetime.fromtimestamp(payload.collected_at_unix, tz=timezone.utc)
    manager = (payload.manager or "dpkg").strip().lower()
    if manager not in {"dpkg", "rpm"}:
        manager = "dpkg"

    db.execute(delete(HostPackage).where(HostPackage.host_id == host.id))
    db.execute(delete(HostCVEStatus).where(HostCVEStatus.host_id == host.id))
    for p in payload.packages:
        name = p.get("name")
        ver = p.get("version")
        if not name or not ver:
            continue
        db.add(
            HostPackage(
                host_id=host.id,
                name=name,
                version=ver,
                arch=p.get("arch", "amd64"),
                manager=manager,
                collected_at=collected_at,
            )
        )

    host.last_seen = datetime.now(timezone.utc)
    db.commit()
    return {"ok": True}


@router.post("/inventory/package-updates")
def agent_inventory_package_updates(payload: PackageUpdatesInventory, request: Request, db: Session = Depends(get_db)):
    _ensure_agent_identity(request, payload.agent_id)
    host = db.execute(select(Host).where(Host.agent_id == payload.agent_id)).scalar_one_or_none()
    if not host:
        _audit_unknown_agent(db, request, payload.agent_id, "inventory_package_updates")
        raise HTTPException(404, "unknown agent")

    checked_at = datetime.fromtimestamp(payload.checked_at_unix, tz=timezone.utc)

    # Persist host-level reboot-needed flag if provided
    if payload.reboot_required is not None and hasattr(host, "reboot_required"):
        host.reboot_required = bool(payload.reboot_required)

    db.execute(delete(HostPackageUpdate).where(HostPackageUpdate.host_id == host.id))

    # Dedupe + sanitize package names coming from agents.
    # Some apt frontends can emit lines like "WARNING:" which should not become package rows.
    seen: set[str] = set()
    for u in payload.updates:
        name = (u.name or "").strip()
        if not name:
            continue
        if name.upper().startswith("WARNING"):
            continue
        # Basic allowlist: dpkg package names are typically [a-z0-9][a-z0-9+.-]+
        # Keep it permissive but exclude obviously bad tokens.
        if any(ch.isspace() for ch in name) or name.endswith(":"):
            continue

        if name in seen:
            continue
        seen.add(name)

        db.add(
            HostPackageUpdate(
                host_id=host.id,
                name=name,
                installed_version=u.installed_version,
                candidate_version=u.candidate_version,
                is_security=bool(getattr(u, "is_security", None) or False),
                update_available=True,
                checked_at=checked_at,
            )
        )

    host.last_seen = datetime.now(timezone.utc)
    db.commit()
    return {"ok": True, "updates": len(payload.updates), "checked_at": checked_at.isoformat()}


@router.get("/next-job")
async def agent_next_job(agent_id: str, request: Request, db: Session = Depends(get_db)):
    _ensure_agent_identity(request, agent_id)
    host = db.execute(select(Host).where(Host.agent_id == agent_id)).scalar_one_or_none()
    if not host:
        _audit_unknown_agent(db, request, agent_id, "next_job")
        raise HTTPException(404, "unknown agent")

    host.last_seen = datetime.now(timezone.utc)
    db.commit()

    # Primary: in-memory dispatcher queue (fast path)
    job = await dispatcher.pop_job(agent_id, timeout=settings.agent_poll_timeout_seconds)
    if job is not None:
        job_key = str((job or {}).get("job_id") or "").strip()
        if job_key:
            row = (
                db.execute(
                    select(JobRun, Job)
                    .join(Job, Job.id == JobRun.job_id)
                    .where(Job.job_key == job_key, JobRun.agent_id == agent_id)
                )
                .first()
            )
            if row:
                run, _job_row = row
                job = _with_job_nonce(job, run)
                db.commit()
                return {"job": job}
        return {"job": job}

    # Fallback: DB-backed dispatch for queued jobs.
    # This avoids jobs getting stuck in "queued" forever after server restarts
    # (in-memory queues are lost on restart).
    now = datetime.now(timezone.utc)

    def build_agent_payload(job_row: Job, agent_id: str) -> dict:
        t = job_row.job_type
        payload = job_row.payload or {}

        if t == "cve-check":
            return {"job_id": job_row.job_key, "type": "cve-check", "cve": payload.get("cve")}
        if t == "dist-upgrade":
            return {"job_id": job_row.job_key, "type": "dist-upgrade"}
        if t == "inventory-now":
            return {"job_id": job_row.job_key, "type": "inventory-now"}
        if t == "query-pkg-version":
            return {"job_id": job_row.job_key, "type": "query-pkg-version", "packages": payload.get("packages") or []}
        if t == "disk-cleanup":
            return {
                "job_id": job_row.job_key,
                "type": "disk-cleanup",
                "dry_run": bool(payload.get("dry_run", True)),
                "cleanup_actions": payload.get("actions") or [],
            }
        if t == "pkg-upgrade":
            packages = payload.get("packages") or []
            by = payload.get("packages_by_agent") or {}
            pkgs = by.get(agent_id) or packages
            return {"job_id": job_row.job_key, "type": "pkg-upgrade", "packages": pkgs or []}

        # Unknown job type: return minimal shape; agent will report failure.
        return {"job_id": job_row.job_key, "type": t}

    with transaction(db):
        row = (
            db.execute(
                select(JobRun, Job)
                .join(Job, Job.id == JobRun.job_id)
                .where(JobRun.agent_id == agent_id, JobRun.status == "queued")
                .order_by(Job.created_at.asc())
                .limit(1)
            )
            .first()
        )

        if not row:
            return {"job": None}

        run, job_row = row
        run.status = "running"
        run.started_at = run.started_at or now

        return {"job": _with_job_nonce(build_agent_payload(job_row, agent_id), run)}


@router.post("/job-event")
def agent_job_event(payload: JobEvent, request: Request, db: Session = Depends(get_db)):
    _ensure_agent_identity(request, payload.agent_id)
    job = db.execute(select(Job).where(Job.job_key == payload.job_id)).scalar_one_or_none()
    if not job:
        raise HTTPException(404, "unknown job")

    run = db.execute(
        select(JobRun).where(JobRun.job_id == job.id, JobRun.agent_id == payload.agent_id)
    ).scalar_one_or_none()
    if not run:
        _audit_unknown_agent(db, request, payload.agent_id, "job_event_unknown_run")
        raise HTTPException(404, "unknown job run")

    expected_nonce = (getattr(run, "job_nonce", None) or "").strip()
    if expected_nonce and payload.job_nonce != expected_nonce:
        try:
            log_event(
                db,
                action="agent.job_event.invalid_nonce",
                actor=None,
                request=request,
                target_type="job_run",
                target_id=payload.job_id,
                meta={"agent_id": payload.agent_id, "status": payload.status},
            )
            db.commit()
        except Exception:
            try:
                db.rollback()
            except Exception:
                pass
        raise HTTPException(403, "invalid job nonce")

    now = datetime.now(timezone.utc)
    if payload.status == "running":
        run.status = "running"
        run.started_at = run.started_at or now
    elif payload.status in ("success", "failed"):
        run.status = payload.status
        run.finished_at = now
        run.exit_code = payload.exit_code
        run.stdout = payload.stdout
        run.stderr = payload.stderr
        run.error = payload.error
    else:
        raise HTTPException(400, "invalid status")

    host = db.execute(select(Host).where(Host.agent_id == payload.agent_id)).scalar_one_or_none()
    if host:
        host.last_seen = now

    # Persist CVE check results (best-effort)
    if payload.status in ("success", "failed") and job.job_type == "cve-check" and payload.stdout:
        try:
            import json

            host = db.execute(select(Host).where(Host.agent_id == payload.agent_id)).scalar_one_or_none()
            if host:
                data = json.loads(payload.stdout or "{}")
                cve = str(data.get("cve") or job.payload.get("cve") or "").strip().upper()
                if cve:
                    affected = bool(data.get("affected") or False)
                    summary = (str(data.get("summary") or "") or "").strip() or None
                    raw = (str(data.get("raw") or "") or "").strip() or None

                    row = db.execute(
                        select(HostCVEStatus).where(HostCVEStatus.host_id == host.id, HostCVEStatus.cve == cve)
                    ).scalar_one_or_none()
                    if not row:
                        row = HostCVEStatus(host_id=host.id, cve=cve)
                        db.add(row)

                    row.affected = affected
                    row.summary = summary
                    row.raw = raw
                    row.checked_at = now
        except Exception:
            # best-effort
            try:
                db.rollback()
            except Exception:
                pass

    # Package upgrades change installed versions and may resolve CVEs. Invalidate stale
    # host CVE results immediately and queue inventory so package snapshots catch up.
    if payload.status == "success" and job.job_type in ("pkg-upgrade", "pkg-install", "pkg-reinstall", "dist-upgrade"):
        try:
            with db.begin_nested():
                host = db.execute(select(Host).where(Host.agent_id == payload.agent_id)).scalar_one_or_none()
                if host:
                    db.execute(delete(HostCVEStatus).where(HostCVEStatus.host_id == host.id))

                    # Avoid enqueueing duplicate refreshes if one is already pending/running for this host.
                    existing_refresh = (
                        db.execute(
                            select(JobRun)
                            .join(Job, Job.id == JobRun.job_id)
                            .where(
                                Job.job_type == "inventory-now",
                                JobRun.agent_id == payload.agent_id,
                                JobRun.status.in_(("queued", "running")),
                            )
                            .limit(1)
                        )
                        .scalar_one_or_none()
                    )
                    if not existing_refresh:
                        create_job_with_runs(
                            db=db,
                            job_type="inventory-now",
                            payload={"reason": f"post-{job.job_type}", "source_job_id": job.job_key},
                            agent_ids=[payload.agent_id],
                            commit=False,
                            created_by=job.created_by,
                        )
        except Exception:
            # best-effort cache invalidation/refresh scheduling
            pass

    # Persist package update availability cache when an update-check job completes
    if payload.status == "success" and job.job_type == "query-pkg-updates" and payload.stdout:
        try:
            import json

            host = db.execute(select(Host).where(Host.agent_id == payload.agent_id)).scalar_one_or_none()
            if host:
                data = json.loads(payload.stdout or "{}")
                checked_at_str = data.get("checked_at")
                try:
                    checked_at = (
                        datetime.fromisoformat(checked_at_str.replace("Z", "+00:00"))
                        if checked_at_str
                        else now
                    )
                except Exception:
                    checked_at = now

                # host-level reboot flag
                if hasattr(host, "reboot_required"):
                    host.reboot_required = bool(data.get("reboot_required") or False)

                updates = data.get("updates", []) or []
                db.execute(delete(HostPackageUpdate).where(HostPackageUpdate.host_id == host.id))
                for u in updates:
                    if not isinstance(u, dict):
                        continue
                    name = str(u.get("name") or "").strip()
                    if not name:
                        continue
                    db.add(
                        HostPackageUpdate(
                            host_id=host.id,
                            name=name,
                            installed_version=u.get("installed_version"),
                            candidate_version=u.get("candidate_version"),
                            is_security=bool(u.get("is_security") or False),
                            update_available=True,
                            checked_at=checked_at,
                        )
                    )
        except Exception:
            # Best-effort caching
            pass

    # Persist a lightweight metrics snapshot when a metrics job completes
    if payload.status == "success" and job.job_type == "query-metrics" and payload.stdout:
        try:
            import json

            host = db.execute(select(Host).where(Host.agent_id == payload.agent_id)).scalar_one_or_none()
            if host:
                data = json.loads(payload.stdout or "{}")
                metrics = data.get("metrics") if isinstance(data, dict) else None
                if isinstance(metrics, dict):
                    cpu = metrics.get("cpu") if isinstance(metrics.get("cpu"), dict) else {}
                    disk = metrics.get("disk_usage") if isinstance(metrics.get("disk_usage"), dict) else {}
                    mem = metrics.get("memory") if isinstance(metrics.get("memory"), dict) else {}

                    snap = HostMetricsSnapshot(
                        agent_id=payload.agent_id,
                        disk_percent_used=str(disk.get("percent_used")) if disk.get("percent_used") is not None else None,
                        mem_percent_used=str(mem.get("percent_used")) if mem.get("percent_used") is not None else None,
                        load_1min=str(cpu.get("load_1min")) if cpu.get("load_1min") is not None else None,
                        vcpus=int(cpu.get("vcpus")) if cpu.get("vcpus") is not None else None,
                    )
                    db.add(snap)

                    if cpu.get("load_1min") is not None:
                        db.add(
                            HostLoadMetric(
                                agent_id=payload.agent_id,
                                load_1min=str(cpu.get("load_1min")),
                                load_5min=str(cpu.get("load_5min")),
                                load_15min=str(cpu.get("load_15min")),
                            )
                        )

                    db.commit()

                    # Retention: keep last 7 days
                    cutoff = datetime.now(timezone.utc) - timedelta(days=7)
                    db.execute(
                        delete(HostLoadMetric).where(
                            HostLoadMetric.agent_id == payload.agent_id,
                            HostLoadMetric.recorded_at < cutoff,
                        )
                    )
                    db.execute(
                        delete(HostMetricsSnapshot).where(
                            HostMetricsSnapshot.agent_id == payload.agent_id,
                            HostMetricsSnapshot.recorded_at < cutoff,
                        )
                    )
                    db.commit()
        except Exception:
            # Best-effort caching
            try:
                db.rollback()
            except Exception:
                pass

    db.commit()
    return {"ok": True}
