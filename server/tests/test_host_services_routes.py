from conftest import bootstrap_test_app


def test_service_control_route_exists_and_returns_host_not_found(monkeypatch, auth_client_factory):
    app = bootstrap_test_app(monkeypatch)

    with auth_client_factory(app) as (client, headers):
        resp = client.post("/hosts/nonexistent-agent/services/ssh/restart", headers=headers)
        assert resp.status_code == 404, resp.text
        assert resp.json().get("detail") == "Host not found"
