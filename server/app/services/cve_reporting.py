from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from packaging.version import InvalidVersion
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import settings
from ..models import CVEDefinition, CVEPackage, Host, HostPackage, HostPackageUpdate


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
        return None


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
