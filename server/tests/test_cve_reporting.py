import importlib
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select


@pytest.fixture()
def app(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "sqlite+pysqlite:///:memory:")
    monkeypatch.setenv("BOOTSTRAP_PASSWORD", "admin-password-123")
    monkeypatch.setenv("MFA_REQUIRE_FOR_PRIVILEGED", "false")
    monkeypatch.setenv("DB_REQUIRE_MIGRATIONS_UP_TO_DATE", "false")
    monkeypatch.setenv("MAINTENANCE_WINDOW_TIMEZONE", "Europe/Tallinn")
    monkeypatch.setenv("METRICS_BACKGROUND_REFRESH_SECONDS", "0")

    app_factory = importlib.import_module("app.app_factory")
    return app_factory.create_app()


def _login(client: TestClient):
    r = client.post("/auth/login", json={"username": "admin", "password": "admin-password-123"})
    assert r.status_code == 200, r.text


def test_hourly_cve_report_and_patch_cronjob_created(app, monkeypatch):
    from app.db import SessionLocal
    from app.models import CVEDefinition, CVEPackage, CronJob, Host, HostPackage, HostPackageUpdate
    from app.services import cve_reporting

    sent = {}

    def fake_send_report_via_smtp(*, recipient: str, subject: str, body: str):
        sent["recipient"] = recipient
        sent["subject"] = subject
        sent["body"] = body

    monkeypatch.setattr(cve_reporting, "send_report_via_smtp", fake_send_report_via_smtp)
    monkeypatch.setattr("app.services.cve_sync.cve_sync_loop", lambda stop_event: stop_event.wait())
    monkeypatch.setattr("app.services.cve_reporting.cve_reporting_loop", lambda stop_event: stop_event.wait())

    with TestClient(app) as client:
        _login(client)

        with SessionLocal() as db:
            host = Host(
                agent_id="agent-1",
                hostname="srv1",
                os_id="ubuntu",
                os_version="Ubuntu 24.04 noble",
                last_seen=datetime.now(timezone.utc),
                labels={},
            )
            db.add(host)
            db.flush()

            db.add(
                HostPackage(
                    host_id=host.id,
                    name="openssl",
                    arch="amd64",
                    version="1.0.0",
                    manager="apt",
                    collected_at=datetime.now(timezone.utc),
                )
            )
            db.add(
                HostPackageUpdate(
                    host_id=host.id,
                    name="openssl",
                    installed_version="1.0.0",
                    candidate_version="1.0.2",
                    is_security=True,
                    update_available=True,
                    checked_at=datetime.now(timezone.utc),
                )
            )
            db.add(CVEDefinition(cve_id="CVE-2026-0001", definition_data={"severity": 8.4}, severity="8.4"))
            db.add(
                CVEPackage(
                    cve_id="CVE-2026-0001",
                    package_name="openssl",
                    release="noble",
                    fixed_version="1.0.2",
                    status="released",
                    severity="8.4",
                )
            )
            db.commit()

            result = cve_reporting.run_hourly_report_once(db)
            assert result["sent"] is True
            assert result["finding_count"] >= 1

            findings = cve_reporting.collect_high_severity_findings(db)
            ours = [it for it in findings if it.agent_id == "agent-1" and it.cve_id == "CVE-2026-0001"]
            assert len(ours) == 1

            cron = db.execute(select(CronJob).where(CronJob.name == "Auto patch high severity CVEs at 03:00")).scalar_one()
            assert cron.action == "security-campaign"
            assert cron.status == "scheduled"
            assert "agent-1" in (cron.selector or {}).get("agent_ids", [])
            assert cron.payload["schedule"]["kind"] == "daily"
            assert cron.payload["schedule"]["time_hhmm"] == "03:00"

    assert sent["recipient"] == "imre@localhost"
    assert "Affected packages:" in sent["body"]
    assert "package=openssl" in sent["body"]
    assert "srv1" in sent["body"]


def test_version_compare_handles_debian_epoch_when_apt_pkg_unavailable(monkeypatch):
    import builtins
    from app.services import cve_reporting

    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "apt_pkg":
            raise ImportError("apt_pkg unavailable")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)

    assert cve_reporting._version_lt("2.10.1-6ubuntu1.3", "0:2.10.1-6ubuntu1.2") is False
    assert cve_reporting._version_lt("2.10.1-6ubuntu1.1", "0:2.10.1-6ubuntu1.2") is True


def test_hourly_cve_report_skips_offline_hosts(app, monkeypatch):
    from app.db import SessionLocal
    from app.models import CVEDefinition, CVEPackage, Host, HostPackage
    from app.services import cve_reporting

    sent = {"count": 0, "body": None}

    def fake_send_report_via_smtp(*, recipient: str, subject: str, body: str):
        sent["count"] += 1
        sent["body"] = body

    monkeypatch.setattr(cve_reporting, "send_report_via_smtp", fake_send_report_via_smtp)
    monkeypatch.setattr("app.services.cve_sync.cve_sync_loop", lambda stop_event: stop_event.wait())
    monkeypatch.setattr("app.services.cve_reporting.cve_reporting_loop", lambda stop_event: stop_event.wait())

    with TestClient(app) as client:
        _login(client)

        with SessionLocal() as db:
            host = Host(
                agent_id="agent-2",
                hostname="srv2",
                os_id="ubuntu",
                os_version="Ubuntu 24.04 noble",
                last_seen=datetime.now(timezone.utc) - timedelta(hours=2),
                labels={},
            )
            db.add(host)
            db.flush()
            db.add(
                HostPackage(
                    host_id=host.id,
                    name="openssl",
                    arch="amd64",
                    version="1.0.0",
                    manager="apt",
                    collected_at=datetime.now(timezone.utc),
                )
            )
            db.add(CVEDefinition(cve_id="CVE-2026-0002", definition_data={"severity": 9.1}, severity="9.1"))
            db.add(
                CVEPackage(
                    cve_id="CVE-2026-0002",
                    package_name="openssl",
                    release="noble",
                    fixed_version="1.0.2",
                    status="released",
                    severity="9.1",
                )
            )
            db.commit()

            result = cve_reporting.run_hourly_report_once(db)
            if result["sent"]:
                assert sent["body"] is not None
                assert "srv2" not in sent["body"]
                assert "agent-2" not in sent["body"]
            else:
                assert result["finding_count"] == 0

    if sent["body"] is not None:
        assert "srv2" not in sent["body"]
        assert "agent-2" not in sent["body"]
