from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from ..config import settings
from ..db import get_db
from ..dispatcher import dispatcher
from ..models import Host, HostCVEStatus, HostLoadMetric, HostMetricsSnapshot, HostPackage, HostPackageUpdate, Job, JobRun
from ..schemas import AgentRegister, JobEvent, PackageUpdatesInventory, PackagesInventory
from ..services.agents import get_client_ip
from ..services.agent_auth import require_agent_token
from ..services.db_utils import transaction

router = APIRouter(prefix="/agent", tags=["agent"])


@router.post("/register")
def agent_register(payload: AgentRegister, request: Request, db: Session = Depends(get_db)):
    require_agent_token(request)
    host = db.execute(select(Host).where(Host.agent_id == payload.agent_id)).scalar_one_or_none()
    now = datetime.now(timezone.utc)

    client_ip = get_client_ip(request)

    if not host:
        host_data = {
            "agent_id": payload.agent_id,
            "hostname": payload.hostname,
            "fqdn": payload.fqdn,
            "os_id": payload.os_id,
            "os_version": payload.os_version,
            "kernel": payload.kernel,
            "labels": payload.labels or {},
            "last_seen": now,
        }
        if client_ip and hasattr(Host, "ip_address"):
            host_data["ip_address"] = client_ip
        host = Host(**host_data)
        db.add(host)
    else:
        host.hostname = payload.hostname
        host.fqdn = payload.fqdn
        if client_ip and hasattr(host, "ip_address"):
            host.ip_address = client_ip
        host.os_id = payload.os_id
        host.os_version = payload.os_version
        host.kernel = payload.kernel
        host.labels = payload.labels or {}
        host.last_seen = now

    db.commit()
    return {"ok": True}


@router.post("/heartbeat")
def agent_heartbeat(agent_id: str, request: Request, db: Session = Depends(get_db)):
    require_agent_token(request)
    host = db.execute(select(Host).where(Host.agent_id == agent_id)).scalar_one_or_none()
    if not host:
        raise HTTPException(404, "unknown agent")

    client_ip = get_client_ip(request)
    if client_ip and hasattr(host, "ip_address"):
        host.ip_address = client_ip

    host.last_seen = datetime.now(timezone.utc)
    db.commit()
    return {"ok": True}


@router.post("/inventory/packages")
def agent_inventory_packages(payload: PackagesInventory, request: Request, db: Session = Depends(get_db)):
    require_agent_token(request)
    host = db.execute(select(Host).where(Host.agent_id == payload.agent_id)).scalar_one_or_none()
    if not host:
        raise HTTPException(404, "unknown agent")

    collected_at = datetime.fromtimestamp(payload.collected_at_unix, tz=timezone.utc)

    db.execute(delete(HostPackage).where(HostPackage.host_id == host.id))
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
                manager="dpkg",
                collected_at=collected_at,
            )
        )

    host.last_seen = datetime.now(timezone.utc)
    db.commit()
    return {"ok": True}


@router.post("/inventory/package-updates")
def agent_inventory_package_updates(payload: PackageUpdatesInventory, request: Request, db: Session = Depends(get_db)):
    require_agent_token(request)
    host = db.execute(select(Host).where(Host.agent_id == payload.agent_id)).scalar_one_or_none()
    if not host:
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
    require_agent_token(request)
    host = db.execute(select(Host).where(Host.agent_id == agent_id)).scalar_one_or_none()
    if not host:
        raise HTTPException(404, "unknown agent")

    host.last_seen = datetime.now(timezone.utc)
    db.commit()

    # Primary: in-memory dispatcher queue (fast path)
    job = await dispatcher.pop_job(agent_id, timeout=settings.agent_poll_timeout_seconds)
    if job is not None:
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

        return {"job": build_agent_payload(job_row, agent_id)}


@router.post("/job-event")
def agent_job_event(payload: JobEvent, request: Request, db: Session = Depends(get_db)):
    require_agent_token(request)
    job = db.execute(select(Job).where(Job.job_key == payload.job_id)).scalar_one_or_none()
    if not job:
        raise HTTPException(404, "unknown job")

    run = db.execute(
        select(JobRun).where(JobRun.job_id == job.id, JobRun.agent_id == payload.agent_id)
    ).scalar_one_or_none()
    if not run:
        raise HTTPException(404, "unknown job run")

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
            # best-effort
            pass

    db.commit()
    return {"ok": True}
