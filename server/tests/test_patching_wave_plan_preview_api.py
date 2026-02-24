import hashlib
import importlib
import sys


def _reload_app_modules():
    for k in list(sys.modules.keys()):
        if k == "app" or k.startswith("app."):
            sys.modules.pop(k, None)


def _bootstrap_app(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "sqlite+pysqlite:///:memory:")
    monkeypatch.setenv("BOOTSTRAP_USERNAME", "admin")
    monkeypatch.setenv("BOOTSTRAP_PASSWORD", "admin-password-123")
    monkeypatch.setenv("MFA_REQUIRE_FOR_PRIVILEGED", "false")
    monkeypatch.setenv("ALLOW_INSECURE_NO_AGENT_TOKEN", "true")
    _reload_app_modules()
    app_factory = importlib.import_module("app.app_factory")
    return app_factory.create_app()


def _register_host(client, agent_id: str, labels: dict | None = None):
    r = client.post(
        "/agent/register",
        json={
            "agent_id": agent_id,
            "hostname": agent_id,
            "fqdn": None,
            "os_id": "ubuntu",
            "os_version": "24.04",
            "kernel": "test",
            "labels": labels or {},
        },
    )
    assert r.status_code == 200, r.text


def _auth_headers(client) -> dict:
    lr = client.post("/auth/login", json={"username": "admin", "password": "admin-password-123"})
    assert lr.status_code == 200, lr.text
    csrf = client.cookies.get("fleet_csrf")
    return {"X-CSRF-Token": csrf} if csrf else {}


def _stable_hash_sort(agent_ids: list[str]) -> list[str]:
    return sorted(set(agent_ids), key=lambda a: (hashlib.sha256(a.encode("utf-8")).hexdigest(), a))


def test_preview_wave_plan_is_deterministic_for_same_target_set(monkeypatch):
    app = _bootstrap_app(monkeypatch)
    from fastapi.testclient import TestClient

    agent_ids = ["srv-c", "srv-a", "srv-e", "srv-b", "srv-d"]
    expected_order = _stable_hash_sort(agent_ids)

    with TestClient(app) as client:
        for aid in agent_ids:
            _register_host(client, aid, labels={"env": "prod"})
        headers = _auth_headers(client)

        payload_a = {
            "agent_ids": agent_ids,
            "wave_plan": {"canary_size": 2, "batch_size": 2},
        }
        payload_b = {
            "agent_ids": list(reversed(agent_ids)),
            "wave_plan": {"canary_size": 2, "batch_size": 2},
        }

        ra = client.post("/patching/campaigns/security-updates/preview", json=payload_a, headers=headers)
        rb = client.post("/patching/campaigns/security-updates/preview", json=payload_b, headers=headers)
        assert ra.status_code == 200, ra.text
        assert rb.status_code == 200, rb.text

        pa = ra.json()
        pb = rb.json()
        assert pa["resolved_agent_ids"] == expected_order
        assert pb["resolved_agent_ids"] == expected_order
        assert pa["waves"] == pb["waves"]
        assert pa["rings"] == pb["rings"]


def test_preview_wave_plan_response_shape(monkeypatch):
    app = _bootstrap_app(monkeypatch)
    from fastapi.testclient import TestClient

    with TestClient(app) as client:
        _register_host(client, "srv-001", labels={"env": "prod"})
        _register_host(client, "srv-002", labels={"env": "prod"})
        _register_host(client, "srv-003", labels={"env": "prod"})
        _register_host(client, "srv-004", labels={"env": "dev"})
        headers = _auth_headers(client)

        r = client.post(
            "/patching/campaigns/security-updates/preview",
            json={"labels": {"env": "prod"}, "wave_plan": {"canary_size": 1, "batch_size": 2}},
            headers=headers,
        )
        assert r.status_code == 200, r.text
        data = r.json()

        assert data["model"] == "canary-batch-v1"
        assert data["selector"]["labels"] == {"env": "prod"}
        assert data["total_hosts"] == 3
        assert data["config"] == {"canary_size": 1, "batch_size": 2}
        assert data["waves"][0]["name"] == "canary"
        assert data["waves"][0]["size"] == 1
        assert data["waves"][1]["name"] == "batch-1"
        assert data["waves"][1]["size"] == 2
        assert len(data["rings"]) == 2


def test_preview_wave_plan_validation(monkeypatch):
    app = _bootstrap_app(monkeypatch)
    from fastapi.testclient import TestClient

    with TestClient(app) as client:
        _register_host(client, "srv-001", labels={"env": "prod"})
        headers = _auth_headers(client)

        bad_plan = client.post(
            "/patching/campaigns/security-updates/preview",
            json={"agent_ids": ["srv-001"], "wave_plan": {"canary_size": 0, "batch_size": 1}},
            headers=headers,
        )
        assert bad_plan.status_code == 400, bad_plan.text
        assert "wave_plan.canary_size" in bad_plan.text

        bad_shape = client.post(
            "/patching/campaigns/security-updates/preview",
            json={"agent_ids": ["srv-001"], "wave_plan": []},
            headers=headers,
        )
        assert bad_shape.status_code == 400, bad_shape.text
        assert "wave_plan must be an object" in bad_shape.text

        no_targets = client.post(
            "/patching/campaigns/security-updates/preview",
            json={"labels": {"env": "missing"}},
            headers=headers,
        )
        assert no_targets.status_code == 400, no_targets.text
        assert "No targets resolved" in no_targets.text
