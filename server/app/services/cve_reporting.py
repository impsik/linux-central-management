from __future__ import annotations

import asyncio
import logging
import smtplib
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from email.utils import format_datetime
from zoneinfo import ZoneInfo

from packaging.version import InvalidVersion
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import settings
from ..db import SessionLocal
from ..models import AppUser, CVEDefinition, CVEPackage, CronJob, Host, HostPackage, HostPackageUpdate
from .db_utils import transaction

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class SeverityFinding:
    host_id: object
    agent_id: str
    hostname: str
    package_name: str
    installed_version: str
    candidate_version: str | None
    cve_id: str
    severity: float
    fixed_version: str
    release: str


@dataclass(frozen=True)
class PackageSeverityFinding:
    host_id: object
    agent_id: str
    hostname: str
    package_name: str
    installed_version: str
    candidate_version: str | None
    severity: float
    fixed_version: str
    release: str
    cve_ids: tuple[str, ...]

    @property
    def cve_count(self) -> int:
        return len(self.cve_ids)


def _online_cutoff() -> datetime:
    grace = max(5, int(getattr(settings, "agent_online_grace_seconds", 30) or 30))
    return datetime.now(timezone.utc) - timedelta(seconds=grace)


def _host_release_codename(host: Host) -> str | None:
    os_version = str(getattr(host, "os_version", "") or "").strip().lower()
    if not os_version:
        return None
    if "jammy" in os_version or "22.04" in os_version:
        return "jammy"
    if "noble" in os_version or "24.04" in os_version:
        return "noble"
    if "focal" in os_version or "20.04" in os_version:
        return "focal"
    return None


def _parse_severity(value) -> float | None:
    if value is None:
        return None
    try:
        return float(value)
    except Exception:
        text = str(value).strip().lower()
        # Ubuntu OVAL uses textual priorities rather than CVSS numbers.
        # Map them to stable numeric buckets so UI thresholds still work.
        priority_scores = {
            "negligible": 0.1,
            "low": 3.9,
            "medium": 6.9,
            "high": 8.9,
            "critical": 10.0,
        }
        return priority_scores.get(text)


def _version_lt(installed: str, fixed: str) -> bool:
    if not installed or not fixed:
        return False
    try:
        import apt_pkg

        try:
            apt_pkg.init_system()
        except Exception:
            pass
        return apt_pkg.version_compare(str(installed), str(fixed)) < 0
    except Exception:
        try:
            from packaging.version import Version

            return Version(str(installed)) < Version(str(fixed))
        except (InvalidVersion, Exception):
            return str(installed) != str(fixed)


def _load_cve_severity_map(db: Session, cve_ids: list[str]) -> dict[str, float]:
    rows = db.execute(select(CVEDefinition).where(CVEDefinition.cve_id.in_(cve_ids))).scalars().all()
    result: dict[str, float] = {}
    for row in rows:
        data = row.definition_data if isinstance(row.definition_data, dict) else {}
        sev = _parse_severity(getattr(row, "severity", None) or data.get("severity"))
        if sev is not None:
            result[str(row.cve_id)] = sev
    return result


def collect_high_severity_findings(db: Session, *, min_severity: float = 7.0) -> list[SeverityFinding]:
    findings: list[SeverityFinding] = []
    cutoff = _online_cutoff()
    hosts = (
        db.execute(select(Host).where(Host.last_seen.is_not(None), Host.last_seen >= cutoff))
        .scalars()
        .all()
    )
    if not hosts:
        return findings

    host_ids = [h.id for h in hosts]
    pkg_rows = db.execute(select(HostPackage).where(HostPackage.host_id.in_(host_ids))).scalars().all()
    update_rows = db.execute(select(HostPackageUpdate).where(HostPackageUpdate.host_id.in_(host_ids))).scalars().all()

    pkg_map = {(row.host_id, row.name): row for row in pkg_rows}
    upd_map = {(row.host_id, row.name): row for row in update_rows if bool(row.update_available)}

    host_release_map = {host.id: _host_release_codename(host) for host in hosts}
    all_pkg_names = sorted({row.name for row in pkg_rows})
    releases = sorted({r for r in host_release_map.values() if r})
    if not all_pkg_names or not releases:
        return findings

    cve_rows = (
        db.execute(
            select(CVEPackage).where(CVEPackage.release.in_(releases), CVEPackage.package_name.in_(all_pkg_names))
        )
        .scalars()
        .all()
    )
    severity_map = _load_cve_severity_map(db, sorted({str(r.cve_id) for r in cve_rows}))

    by_release_pkg: dict[tuple[str, str], list[CVEPackage]] = {}
    for row in cve_rows:
        by_release_pkg.setdefault((str(row.release), str(row.package_name)), []).append(row)

    for host in hosts:
        release = host_release_map.get(host.id)
        if not release:
            continue
        host_pkg_names = sorted({name for (hid, name) in pkg_map.keys() if hid == host.id})
        for pkg_name in host_pkg_names:
            pkg = pkg_map.get((host.id, pkg_name))
            if not pkg:
                continue
            for cve_row in by_release_pkg.get((release, pkg_name), []):
                severity = severity_map.get(str(cve_row.cve_id)) or _parse_severity(getattr(cve_row, "severity", None))
                if severity is None or severity <= float(min_severity):
                    continue
                if not _version_lt(pkg.version, cve_row.fixed_version):
                    continue
                upd = upd_map.get((host.id, pkg_name))
                findings.append(
                    SeverityFinding(
                        host_id=host.id,
                        agent_id=str(host.agent_id),
                        hostname=str(host.hostname),
                        package_name=str(pkg_name),
                        installed_version=str(pkg.version),
                        candidate_version=str(upd.candidate_version) if upd and upd.candidate_version else None,
                        cve_id=str(cve_row.cve_id),
                        severity=severity,
                        fixed_version=str(cve_row.fixed_version),
                        release=release,
                    )
                )

    findings.sort(key=lambda item: (-item.severity, item.hostname, item.package_name, item.cve_id))
    return findings


def merge_findings_by_package(findings: list[SeverityFinding]) -> list[PackageSeverityFinding]:
    grouped: dict[tuple[object, str, str], list[SeverityFinding]] = {}
    for item in findings:
        grouped.setdefault((item.host_id, item.release, item.package_name), []).append(item)

    merged: list[PackageSeverityFinding] = []
    for rows in grouped.values():
        rows = sorted(rows, key=lambda item: (-item.severity, item.cve_id))
        top = rows[0]
        fixed_versions = sorted({item.fixed_version for item in rows if item.fixed_version})
        merged.append(
            PackageSeverityFinding(
                host_id=top.host_id,
                agent_id=top.agent_id,
                hostname=top.hostname,
                package_name=top.package_name,
                installed_version=top.installed_version,
                candidate_version=top.candidate_version,
                severity=max(item.severity for item in rows),
                fixed_version=", ".join(fixed_versions),
                release=top.release,
                cve_ids=tuple(sorted({item.cve_id for item in rows})),
            )
        )

    merged.sort(key=lambda item: (-item.severity, item.hostname, item.package_name))
    return merged


def format_report(findings: list[SeverityFinding]) -> str:
    now = datetime.now(timezone.utc)
    package_findings = merge_findings_by_package(findings)
    lines = [
        f"High severity CVE report generated at {now.isoformat()}",
        f"Threshold: severity > 7",
        f"Affected packages: {len(package_findings)}",
        f"Merged CVEs: {len(findings)}",
        "",
    ]
    current_host = None
    for item in package_findings:
        if item.hostname != current_host:
            if current_host is not None:
                lines.append("")
            current_host = item.hostname
            lines.append(f"Host: {item.hostname} ({item.agent_id}) [{item.release}]")
        candidate = item.candidate_version or "unknown"
        lines.append(
            f"- package={item.package_name} severity={item.severity:.1f} installed={item.installed_version} candidate={candidate} fixed={item.fixed_version} cve_count={item.cve_count}"
        )
    return "\n".join(lines).rstrip() + "\n"


def send_report_via_smtp(*, recipient: str, subject: str, body: str) -> None:
    msg = EmailMessage()
    msg["To"] = recipient
    msg["From"] = "linux-central-management@localhost"
    msg["Subject"] = subject
    msg["Date"] = format_datetime(datetime.now(timezone.utc))
    msg.set_content(body)

    with smtplib.SMTP("localhost") as smtp:
        smtp.send_message(msg)


def next_local_3am_utc(now: datetime | None = None) -> datetime:
    tz_name = str(getattr(settings, "maintenance_window_timezone", "Europe/Tallinn") or "Europe/Tallinn")
    try:
        tz = ZoneInfo(tz_name)
    except Exception:
        tz = timezone.utc
    base = (now or datetime.now(timezone.utc)).astimezone(tz)
    candidate = datetime(base.year, base.month, base.day, 3, 0, 0, tzinfo=tz)
    if candidate <= base:
        candidate = candidate + timedelta(days=1)
    return candidate.astimezone(timezone.utc)


def ensure_patch_cronjob(db: Session, *, findings: list[SeverityFinding]) -> str | None:
    if not findings:
        return None
    agent_ids = sorted({item.agent_id for item in findings})
    target_user = db.execute(select(AppUser).where(AppUser.username == "admin")).scalar_one_or_none()
    if not target_user:
        logger.warning("Cannot create CVE patch cronjob: admin user missing")
        return None

    existing = db.execute(select(CronJob).where(CronJob.name == "Auto patch high severity CVEs at 03:00")).scalar_one_or_none()
    run_at = next_local_3am_utc()
    payload = {
        "schedule": {
            "kind": "daily",
            "timezone": str(getattr(settings, "maintenance_window_timezone", "Europe/Tallinn") or "Europe/Tallinn"),
            "time_hhmm": "03:00",
            "weekday": None,
            "day_of_month": None,
        },
        "source": "cve-high-severity-reporter",
        "package_names": sorted({item.package_name for item in findings}),
        "cves": sorted({item.cve_id for item in findings}),
    }

    with transaction(db):
        if existing:
            existing.user_id = target_user.id
            existing.run_at = run_at
            existing.action = "security-campaign"
            existing.payload = payload
            existing.selector = {"agent_ids": agent_ids}
            existing.status = "scheduled"
            existing.started_at = None
            existing.finished_at = None
            existing.last_error = None
            return str(existing.id)

        cj = CronJob(
            user_id=target_user.id,
            name="Auto patch high severity CVEs at 03:00",
            run_at=run_at,
            action="security-campaign",
            payload=payload,
            selector={"agent_ids": agent_ids},
            status="scheduled",
        )
        db.add(cj)
        db.flush()
        return str(cj.id)


def run_hourly_report_once(db: Session, *, min_severity: float = 7.0, recipient: str = "imre@localhost") -> dict[str, object]:
    findings = collect_high_severity_findings(db, min_severity=min_severity)
    cron_id = ensure_patch_cronjob(db, findings=findings)
    if not findings:
        return {"sent": False, "finding_count": 0, "cronjob_id": cron_id}

    body = format_report(findings)
    send_report_via_smtp(
        recipient=recipient,
        subject=f"High severity CVE report ({len(findings)} findings)",
        body=body,
    )
    return {"sent": True, "finding_count": len(findings), "cronjob_id": cron_id}


async def cve_reporting_loop(stop_event: asyncio.Event, *, interval_s: float = 3600.0) -> None:
    while not stop_event.is_set():
        try:
            with SessionLocal() as db:
                run_hourly_report_once(db)
        except Exception:
            logger.exception("CVE reporting tick failed")

        try:
            await asyncio.wait_for(stop_event.wait(), timeout=interval_s)
        except asyncio.TimeoutError:
            pass
