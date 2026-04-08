from datetime import datetime, timedelta, timezone

from conftest import bootstrap_test_app, auth_client_factory


def _future_hhmm(hours_ahead: int) -> str:
    d = datetime.now(timezone.utc) + timedelta(hours=hours_ahead)
    return f"{d.hour:02d}:{d.minute:02d}"


def _seed_host(db, models, *, agent_id: str, env: str):
    db.add(
        models.Host(
            agent_id=agent_id,
            hostname=agent_id,
            os_id="ubuntu",
            os_version="24.04",
            kernel="test",
            labels={"env": env},
        )
    )
    db.commit()


def _seed_window(db, models, *, start_hhmm: str, end_hhmm: str, labels: dict):
    db.add(
        models.AppMaintenanceWindow(
            name="prod-maint-window",
            timezone="UTC",
            start_hhmm=start_hhmm,
            end_hhmm=end_hhmm,
            action_scope=["dist-upgrade", "security-campaign"],
            label_selector=labels,
            enforcement_mode="block",
            enabled=True,
        )
    )
    db.commit()


def test_scoped_window_blocks_dist_upgrade_for_matching_prod_host(monkeypatch, auth_client_factory):
    monkeypatch.setenv("MAINTENANCE_WINDOW_ENABLED", "false")
    app = bootstrap_test_app(monkeypatch, create_schema=True)

    from app.db import SessionLocal
    from app import models

    with SessionLocal() as db:
        _seed_host(db, models, agent_id="srv-prod-001", env="prod")
        _seed_window(db, models, start_hhmm=_future_hhmm(2), end_hhmm=_future_hhmm(3), labels={"env": "prod"})

    with auth_client_factory(app) as (client, headers):
        resp = client.post("/jobs/dist-upgrade", json={"agent_ids": ["srv-prod-001"]}, headers=headers)
        assert resp.status_code == 403, resp.text
        body = resp.json()
        assert body["detail"] == "Action 'dist-upgrade' is blocked outside maintenance window for matching targets"


def test_scoped_window_allows_dist_upgrade_for_non_matching_stage_host(monkeypatch, auth_client_factory):
    monkeypatch.setenv("MAINTENANCE_WINDOW_ENABLED", "false")
    app = bootstrap_test_app(monkeypatch, create_schema=True)

    from app.db import SessionLocal
    from app import models

    with SessionLocal() as db:
        _seed_host(db, models, agent_id="srv-stage-001", env="stage")
        _seed_window(db, models, start_hhmm=_future_hhmm(2), end_hhmm=_future_hhmm(3), labels={"env": "prod"})

    with auth_client_factory(app) as (client, headers):
        resp = client.post("/jobs/dist-upgrade", json={"agent_ids": ["srv-stage-001"], "dry_run": True}, headers=headers)
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["dry_run"] is True
        assert body["type"] == "dist-upgrade"


def test_scoped_window_blocks_security_campaign_for_matching_prod_host(monkeypatch, auth_client_factory):
    monkeypatch.setenv("MAINTENANCE_WINDOW_ENABLED", "false")
    app = bootstrap_test_app(monkeypatch, create_schema=True)

    from app.db import SessionLocal
    from app import models

    with SessionLocal() as db:
        _seed_host(db, models, agent_id="srv-prod-002", env="prod")
        _seed_window(db, models, start_hhmm=_future_hhmm(2), end_hhmm=_future_hhmm(3), labels={"env": "prod"})

    with auth_client_factory(app) as (client, headers):
        now = datetime.now(timezone.utc)
        resp = client.post(
            "/patching/campaigns/security-updates",
            json={
                "agent_ids": ["srv-prod-002"],
                "window_start": now.isoformat(),
                "window_end": (now + timedelta(hours=1)).isoformat(),
            },
            headers=headers,
        )
        assert resp.status_code == 403, resp.text
        body = resp.json()
        assert body["detail"] == "Action 'security-campaign' is blocked outside maintenance window for matching targets"
