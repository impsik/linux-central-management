import asyncio
import json
from contextlib import nullcontext
from types import SimpleNamespace

import pytest


@pytest.mark.parametrize("capabilities", [
    {"unit_file_state": "static", "socket_unit_file_state": "enabled", "can_enable": True, "can_disable": True},
    {"unit_file_state": "static", "socket_unit_file_state": "", "can_enable": False, "can_disable": False},
    {},
])
def test_service_presence_preserves_capabilities_and_old_agent_unknowns(monkeypatch, capabilities):
    monkeypatch.setenv("DATABASE_URL", "sqlite+pysqlite:///:memory:")
    from app.routers import reports

    host = SimpleNamespace(
        agent_id="agent1", hostname="node1", fqdn=None, ip_address="192.0.2.1",
        os_id="ubuntu", os_version="24.04", labels={}, last_seen=None,
    )
    service = {"name": "ssh", "status": "active", "enabled": True, **capabilities}
    monkeypatch.setattr(reports, "_visible_online_hosts", lambda **kwargs: ([host], 0))
    monkeypatch.setattr(reports, "transaction", lambda db: nullcontext())
    monkeypatch.setattr(reports, "create_job_with_runs", lambda **kwargs: SimpleNamespace(job_key="job1", job=SimpleNamespace(id="id1")))

    async def push(**kwargs):
        pass

    async def runs(**kwargs):
        return [SimpleNamespace(agent_id="agent1", status="success", stdout=json.dumps({"services": [service]}))]

    monkeypatch.setattr(reports, "push_job_to_agents", push)
    monkeypatch.setattr(reports, "_wait_for_job_runs", runs)
    output = asyncio.run(reports.service_presence_report(
        service_name="ssh", exact=True, max_hosts=20, db=object(), user=object(),
    ))
    assert output["total"] == 1
    item = output["items"][0]
    assert item["unit_file_state"] == capabilities.get("unit_file_state", "")
    assert item["socket_unit_file_state"] == capabilities.get("socket_unit_file_state", "")
    assert item["can_enable"] is capabilities.get("can_enable")
    assert item["can_disable"] is capabilities.get("can_disable")
