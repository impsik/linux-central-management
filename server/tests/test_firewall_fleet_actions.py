import sys
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import sessionmaker


@pytest.fixture(autouse=True)
def isolated_app_modules(monkeypatch):
    # Settings/engines are initialized on import. Restore the caller's modules
    # so these route tests cannot change the environment of later API tests.
    saved = {name: module for name, module in sys.modules.copy().items()
             if name == "app" or name.startswith("app.")}
    for name in saved:
        sys.modules.pop(name)
    monkeypatch.setenv("DATABASE_URL", "sqlite+pysqlite:///:memory:")
    try:
        yield
    finally:
        for name in list(sys.modules):
            if name == "app" or name.startswith("app."):
                sys.modules.pop(name)
        sys.modules.update(saved)


@pytest.fixture()
def firewall_api(monkeypatch, tmp_path):
    from app import models
    from app.routers import reports
    from app.services.jobs import build_agent_job_payload

    engine = create_engine(
        f"sqlite+pysqlite:///{tmp_path / 'firewall.sqlite'}",
        connect_args={"check_same_thread": False},
    )
    tables = [models.Host, models.AppUser, models.AppUserScope,
              models.Job, models.JobRun, models.AuditEvent]
    models.Host.metadata.create_all(engine, tables=[model.__table__ for model in tables])
    sessions = sessionmaker(bind=engine)
    now = datetime.now(timezone.utc)
    with sessions() as db:
        user = models.AppUser(username="imre", password_hash="unused-test-hash", role="operator")
        db.add(user)
        db.flush()
        actor = SimpleNamespace(id=user.id, username=user.username, role=user.role)
        db.add(models.AppUserScope(user_id=user.id, selector={"env": ["stage"]}))
        for agent_id, labels, last_seen in (
            ("owned", {"owner": "imre"}, now),
            ("scoped", {"owner": "other", "env": "stage"}, now),
            ("unselected", {"owner": "imre"}, now),
            ("foreign", {"owner": "other", "env": "prod"}, now),
            ("offline", {"owner": "imre"}, now - timedelta(minutes=5)),
        ):
            db.add(models.Host(agent_id=agent_id, hostname=agent_id, labels=labels, last_seen=last_seen))
        db.commit()
    monkeypatch.setattr(reports.settings, "agent_online_grace_seconds", 30)
    dispatched = []

    async def push(*, agent_ids, job_payload_builder):
        dispatched.extend((agent_id, job_payload_builder(agent_id)) for agent_id in agent_ids)

    monkeypatch.setattr(reports, "push_job_to_agents", push)

    def get_db():
        with sessions() as db:
            yield db

    app = FastAPI()
    app.include_router(reports.router)
    app.dependency_overrides[reports.get_db] = get_db
    app.dependency_overrides[reports.require_ui_user] = lambda: actor
    try:
        with TestClient(app) as client:
            yield SimpleNamespace(
                client=client, actor=actor, sessions=sessions, models=models,
                dispatched=dispatched, build_payload=build_agent_job_payload,
            )
    finally:
        engine.dispose()


def assert_no_jobs(api):
    assert api.dispatched == []
    with api.sessions() as db:
        for model in (api.models.Job, api.models.JobRun, api.models.AuditEvent):
            assert db.execute(select(func.count()).select_from(model)).scalar_one() == 0


@pytest.mark.parametrize("action", ["enable", "disable"])
def test_firewall_state_uses_selected_visible_online_hosts_and_records_action(firewall_api, action):
    api = firewall_api
    response = api.client.post(f"/reports/firewall-rules/{action}", json={
        "agent_ids": [" owned ", "scoped", "owned", "offline", "foreign", "missing"],
    })
    assert response.status_code == 200, response.text
    result = response.json()
    assert result["action"] == action
    assert result["rule"] == {"action": action}
    assert result["targets"] == ["owned", "scoped"]
    assert result["skipped_offline"] == ["offline"]
    assert result["unknown_or_unavailable"] == ["foreign", "missing"]
    wire = {"job_id": result["job_id"], "type": "firewall-control", "action": action}
    assert api.dispatched == [("owned", wire), ("scoped", wire)]
    with api.sessions() as db:
        job = db.execute(select(api.models.Job)).scalar_one()
        assert job.job_key == result["job_id"]
        assert job.job_type == "firewall-control"
        assert job.payload == {"action": action, "source_context": "firewall-rules"}
        assert job.selector == {"agent_ids": ["owned", "scoped"]}
        assert api.build_payload(job, "owned") == wire
        runs = db.execute(select(api.models.JobRun).order_by(api.models.JobRun.agent_id)).scalars().all()
        assert [(run.agent_id, run.status) for run in runs] == [("owned", "queued"), ("scoped", "queued")]
        assert all(run.job_nonce for run in runs)
        event = db.execute(select(api.models.AuditEvent)).scalar_one()
        assert event.action == f"reports.firewall_rules.{action}"
        assert (event.target_type, event.target_name) == ("firewall", action)
        assert event.actor_username == "imre"
        assert event.meta == {
            "job_id": result["job_id"], "target_count": 2,
            "offline_agent_ids": ["offline"],
            "unknown_or_unavailable_agent_ids": ["foreign", "missing"],
        }


@pytest.mark.parametrize("action", ["enable", "disable"])
def test_admin_firewall_state_action_still_requires_explicit_selection(firewall_api, action):
    api = firewall_api
    api.actor.role = "admin"
    response = api.client.post(f"/reports/firewall-rules/{action}", json={"agent_ids": ["foreign"]})
    assert response.status_code == 200, response.text
    assert response.json()["targets"] == ["foreign"]
    assert [agent_id for agent_id, _ in api.dispatched] == ["foreign"]


@pytest.mark.parametrize("action", ["enable", "disable"])
def test_readonly_cannot_change_firewall_state(firewall_api, action):
    api = firewall_api
    api.actor.role = "readonly"
    response = api.client.post(f"/reports/firewall-rules/{action}", json={"agent_ids": ["owned"]})
    assert response.status_code == 403
    assert_no_jobs(api)


@pytest.mark.parametrize("body", [{}, {"agent_ids": None}, {"agent_ids": []}, {"agent_ids": ["", " \t"]}])
@pytest.mark.parametrize("action", ["enable", "disable"])
def test_firewall_state_action_rejects_empty_selection_instead_of_targeting_fleet(firewall_api, body, action):
    response = firewall_api.client.post(f"/reports/firewall-rules/{action}", json=body)
    assert response.status_code == 400
    assert response.json()["detail"] == "agent_ids is required"
    assert_no_jobs(firewall_api)


@pytest.mark.parametrize("agent_id", ["foreign", "missing", "offline"])
@pytest.mark.parametrize("action", ["enable", "disable"])
def test_firewall_state_action_rejects_selection_without_visible_online_hosts(firewall_api, agent_id, action):
    response = firewall_api.client.post(f"/reports/firewall-rules/{action}", json={"agent_ids": [agent_id]})
    assert response.status_code == 400
    assert "No online matching hosts" in response.json()["detail"]
    assert_no_jobs(firewall_api)


@pytest.mark.parametrize(("action", "rule", "error"), [
    ("allow", {}, "port is required"),
    ("deny", {}, "port is required"),
    ("delete", {}, "port is required"),
    ("allow", {"port": 0}, "port must be between"),
    ("deny", {"port": 65536}, "port must be between"),
    ("delete", {"port": 22, "protocol": "icmp"}, "protocol must be tcp or udp"),
    ("restart", {"port": 22}, "Invalid action"),
])
def test_existing_firewall_rule_validation_is_preserved(firewall_api, action, rule, error):
    response = firewall_api.client.post(f"/reports/firewall-rules/{action}", json={"agent_ids": ["owned"], **rule})
    assert response.status_code == 400
    assert error in response.json()["detail"]
    assert_no_jobs(firewall_api)


@pytest.mark.parametrize("action", ["allow", "deny", "delete"])
@pytest.mark.parametrize(("fields", "normalized", "target_name"), [
    ({"port": 2222, "protocol": " UDP ", "source": " 192.0.2.0/24 "},
     {"port": 2222, "protocol": "udp", "source": "192.0.2.0/24", "service": ""}, "2222/udp"),
    ({"service": " ssh "}, {"port": 0, "protocol": "tcp", "source": "", "service": "ssh"}, "ssh"),
])
def test_existing_rule_actions_keep_payload_and_audit_shape(firewall_api, action, fields, normalized, target_name):
    api = firewall_api
    response = api.client.post(f"/reports/firewall-rules/{action}", json={"agent_ids": ["owned"], **fields})
    assert response.status_code == 200, response.text
    expected = {"action": action, **normalized}
    assert response.json()["rule"] == expected
    with api.sessions() as db:
        job = db.execute(select(api.models.Job)).scalar_one()
        assert job.payload == {**expected, "source_context": "firewall-rules"}
        event = db.execute(select(api.models.AuditEvent)).scalar_one()
        assert event.action == f"reports.firewall_rules.{action}"
        assert (event.target_type, event.target_name) == ("firewall_rule", target_name)
