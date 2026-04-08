from conftest import bootstrap_test_app, login_test_client


def test_dashboard_slo_api_smoke(monkeypatch):
    app = bootstrap_test_app(monkeypatch)

    from fastapi.testclient import TestClient

    with TestClient(app) as client:
        # create host for offline ratio metric
        r = client.post(
            "/agent/register",
            json={
                "agent_id": "srv-001",
                "hostname": "srv-001",
                "os_id": "ubuntu",
                "os_version": "22.04",
                "kernel": "test",
                "labels": {"env": "test"},
            },
        )
        assert r.status_code == 200, r.text

        # login to access dashboard API
        login_test_client(client)

        slo = client.get("/dashboard/slo", params={"hours": 24})
        assert slo.status_code == 200, slo.text
        data = slo.json()

        assert data["window_hours"] == 24
        assert "kpis" in data
        assert "job_success_rate" in data["kpis"]
        assert "median_patch_duration" in data["kpis"]
        assert "auth_error_rate" in data["kpis"]
        assert "offline_host_ratio" in data["kpis"]

        for key in ("job_success_rate", "median_patch_duration", "auth_error_rate", "offline_host_ratio"):
            assert "sample_count" in data["kpis"][key]
            assert "previous_sample_count" in data["kpis"][key]

        csv_resp = client.get("/dashboard/slo.csv", params={"hours": 24, "bucket_hours": 12})
        assert csv_resp.status_code == 200, csv_resp.text
        assert "text/csv" in (csv_resp.headers.get("content-type") or "")
        assert "window_start,window_end,job_success_rate_pct" in csv_resp.text
