from collections import Counter
from datetime import datetime, timedelta, timezone
import sys
from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session, sessionmaker


NOW = datetime(2026, 9, 14, 12, tzinfo=timezone.utc)


@pytest.fixture
def cve_db(monkeypatch):
    saved = {name: module for name, module in sys.modules.copy().items()
             if name == "app" or name.startswith("app.")}
    for name in saved:
        sys.modules.pop(name)
    monkeypatch.setenv("DATABASE_URL", "sqlite+pysqlite:///:memory:")
    from app import models
    from app.services import cve_reporting

    engine = create_engine("sqlite+pysqlite:///:memory:")
    models.Base.metadata.create_all(engine, tables=[model.__table__ for model in (
        models.Host, models.HostPackage, models.HostPackageUpdate, models.CVEDefinition, models.CVEPackage,
    )])
    monkeypatch.setattr(cve_reporting, "_online_cutoff", lambda: NOW - timedelta(seconds=30))
    try:
        yield SimpleNamespace(models=models, service=cve_reporting, engine=engine, sessions=sessionmaker(bind=engine))
    finally:
        engine.dispose()
        for name in list(sys.modules):
            if name == "app" or name.startswith("app."):
                sys.modules.pop(name)
        sys.modules.update(saved)


def add_host(stack, db, name, *, release="24.04", online=True):
    host = stack.models.Host(agent_id=name, hostname=name, os_id="ubuntu", os_version=release,
                             last_seen=NOW if online else NOW - timedelta(hours=1))
    db.add(host)
    db.flush()
    return host


def add_package(stack, db, host, name, version="1.0", *, candidate=None):
    db.add(stack.models.HostPackage(host_id=host.id, name=name, version=version,
                                   arch="amd64", manager="dpkg", collected_at=NOW))
    if candidate is not None:
        db.add(stack.models.HostPackageUpdate(host_id=host.id, name=name, installed_version=version,
                                             candidate_version=candidate, update_available=True, checked_at=NOW))


def add_cve(stack, db, name, *, package="openssl", release="noble", severity="8.9",
            package_severity="critical", data=None):
    db.add(stack.models.CVEDefinition(cve_id=name, severity=severity, definition_data=data or {}))
    db.flush()
    db.add(stack.models.CVEPackage(cve_id=name, package_name=package, release=release,
                                  fixed_version="2.0", severity=package_severity, status="released"))


@pytest.mark.parametrize("unrelated_release", [None, "focal"])
def test_no_relevant_cves_does_not_read_package_inventories(cve_db, unrelated_release):
    stack = cve_db
    with stack.sessions.begin() as db:
        host = add_host(stack, db, "noble-node")
        add_package(stack, db, host, "openssl", candidate="2.0")
        if unrelated_release:
            add_cve(stack, db, "unrelated-release", release=unrelated_release)

    statements = []
    def capture(conn, cursor, statement, parameters, context, executemany):
        statements.append(statement.lower())
    event.listen(stack.engine, "before_cursor_execute", capture)
    with stack.sessions() as db:
        assert stack.service.collect_high_severity_findings(db) == []
    assert statements
    assert not any("host_packages" in sql or "host_package_updates" in sql for sql in statements)


def test_low_severity_cves_do_not_load_installed_versions_or_updates(cve_db):
    stack = cve_db
    with stack.sessions.begin() as db:
        host = add_host(stack, db, "noble-node")
        add_package(stack, db, host, "openssl", candidate="2.0")
        add_cve(stack, db, "threshold", severity="7.0")

    statements = []
    def capture(conn, cursor, statement, parameters, context, executemany):
        statements.append(statement.lower())
    event.listen(stack.engine, "before_cursor_execute", capture)
    with stack.sessions() as db:
        assert stack.service.collect_high_severity_findings(db, min_severity=7.0) == []
    assert any("host_packages.name" in sql for sql in statements)
    assert not any("host_packages.version" in sql or "host_package_updates" in sql for sql in statements)


def test_only_matching_package_rows_are_loaded_and_version_comparisons_are_reused(cve_db, monkeypatch):
    stack = cve_db
    expected_hosts = set()
    with stack.sessions.begin() as db:
        for index in range(12):
            host = add_host(stack, db, f"node-{index:02}")
            expected_hosts.add(host.id)
            add_package(stack, db, host, "openssl", candidate="2.0")
            add_package(stack, db, host, "already-fixed", "3.0")
            add_package(stack, db, host, "low-only", candidate="2.0")
            add_package(stack, db, host, "wrong-release", candidate="2.0")
            for package_index in range(100):
                add_package(stack, db, host, f"irrelevant-{package_index}", candidate="2.0")
        offline = add_host(stack, db, "offline", online=False)
        add_package(stack, db, offline, "openssl", candidate="2.0")
        unknown = add_host(stack, db, "unknown-release", release="unknown")
        add_package(stack, db, unknown, "openssl", candidate="2.0")
        jammy = add_host(stack, db, "jammy", release="22.04")
        add_package(stack, db, jammy, "unrelated")

        # Definition severity wins, including textual/legacy JSON behavior.
        add_cve(stack, db, "stored-high", severity="8.7")
        add_cve(stack, db, "json-high", severity="", data={"severity": "high"})
        add_cve(stack, db, "package-fallback", severity="unscored", data={"severity": 4})
        add_cve(stack, db, "zero-fallback", severity="0", package_severity="high")
        add_cve(stack, db, "threshold", severity="7.0")
        add_cve(stack, db, "stored-low", severity="4")
        add_cve(stack, db, "low-only", package="low-only", severity="6")
        add_cve(stack, db, "fixed", package="already-fixed")
        add_cve(stack, db, "jammy-only", package="wrong-release", release="jammy")

    loaded_packages, loaded_updates = [], []

    class CaptureRows(Session):
        def execute(self, statement, *args, **kwargs):
            result = super().execute(statement, *args, **kwargs)
            if getattr(statement, "is_select", False):
                keys = tuple(result.keys())
                if keys in (("host_id", "name", "version"), ("host_id", "name", "candidate_version")):
                    frozen = result.freeze()
                    target = loaded_packages if keys[-1] == "version" else loaded_updates
                    target.extend(frozen().all())
                    return frozen()
            return result

    comparisons = Counter()
    original_compare = stack.service._version_lt
    def compare(installed, fixed):
        comparisons[(installed, fixed)] += 1
        return original_compare(installed, fixed)
    monkeypatch.setattr(stack.service, "_version_lt", compare)

    with CaptureRows(bind=stack.engine) as db:
        findings = stack.service.collect_high_severity_findings(db)
        assert not any(isinstance(row, (stack.models.HostPackage, stack.models.HostPackageUpdate,
                                       stack.models.CVEPackage)) for row in db.identity_map.values())
    assert len(findings) == 12 * 4
    assert {item.host_id for item in findings} == expected_hosts
    assert {item.cve_id: item.severity for item in findings} == {
        "stored-high": 8.7, "json-high": 8.9, "package-fallback": 10.0, "zero-fallback": 8.9,
    }
    assert all(item.package_name == "openssl" and item.candidate_fixes is True for item in findings)
    assert findings == sorted(findings, key=lambda item: (-item.severity, item.hostname, item.package_name, item.cve_id))
    assert len(loaded_packages) == 24
    assert {row.name for row in loaded_packages} == {"openssl", "already-fixed"}
    assert {row.host_id for row in loaded_packages} == expected_hosts
    assert len(loaded_updates) == 12
    assert {row.name for row in loaded_updates} == {"openssl"}
    assert comparisons == {("1.0", "2.0"): 1, ("2.0", "2.0"): 1, ("3.0", "2.0"): 1}
