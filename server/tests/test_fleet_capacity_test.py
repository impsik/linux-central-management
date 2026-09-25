"""Exercise the simulator against disposable local HTTP handlers, never Fleet DBs."""
import asyncio
import hashlib
import hmac
import json
import sys
import time
from collections import Counter
from pathlib import Path

import pytest
from aiohttp import web

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from scripts import fleet_capacity_test as capacity


def arguments(tmp_path, url="http://127.0.0.1:1", extra=()):
    token = tmp_path / "bootstrap.txt"
    token.write_text("isolated-bootstrap-secret")
    token.chmod(0o600)
    cookie = tmp_path / "cookies.json"
    cookie.write_text(json.dumps({"fleet_session": "isolated-session-secret"}))
    cookie.chmod(0o600)
    return capacity.parse_args([
        "--base-url", url, "--confirm-isolated", "--bootstrap-token-file", str(token),
        "--ui-cookie-file", str(cookie), "--agents", "3", "--agent-prefix", "capacity-unit",
        "--duration-seconds", ".35", "--ramp-up-seconds", ".02", "--inventory-stagger-seconds", ".01",
        "--heartbeat-seconds", ".04", "--inventory-seconds", ".15", "--poll-timeout-seconds", ".08",
        "--poll-sleep-seconds", ".005", "--ui-clients", "3", "--ui-interval-seconds", ".08",
        "--write-concurrency", "1", "--packages-per-host", "10", "--updates-per-host", "3",
        "--ready-file", str(tmp_path / "ready.json"), "--json", str(tmp_path / "report.json"),
        "--csv", str(tmp_path / "requests.csv"), *extra,
    ])


def test_requires_explicit_isolated_target(tmp_path):
    with pytest.raises(SystemExit):
        capacity.parse_args(["--base-url", "http://127.0.0.1:1"])
    with pytest.raises(SystemExit):
        arguments(tmp_path, "https://user:password@example.invalid")
    with pytest.raises(SystemExit):
        arguments(tmp_path, extra=["--heartbeat-seconds", "0"])


def test_package_seed_preserves_real_cve_names_and_pads_deterministically(tmp_path):
    path = tmp_path / "packages.json"
    path.write_text(json.dumps([{"name": "openssl", "version": "3.0.13-0ubuntu3", "arch": "amd64"}]))
    packages = capacity.package_seed(str(path), 850)
    assert len(packages) == len({p["name"] for p in packages}) == 850
    assert packages[0]["name"] == "openssl"
    assert packages == capacity.package_seed(str(path), 850)
    assert capacity.registration("test", 1)["os_version"] == "24.04"


def test_long_poll_wait_is_excluded_from_fast_request_percentiles(tmp_path):
    run = capacity.CapacityRun(arguments(tmp_path))
    run.stats[("steady", "heartbeat")].add(.01, status=200)
    run.stats[("steady", "next-job")].add(25, status=200)
    report = run.report()
    assert report["steady_http_excluding_long_poll"]["p95_ms"] == 10
    assert next(row for row in report["endpoints"] if row["endpoint"] == "next-job")["p95_ms"] == 25000


def test_periodic_work_drops_missed_ticks_instead_of_bursting(tmp_path):
    async def scenario():
        run = capacity.CapacityRun(arguments(tmp_path))
        calls = []
        async def slow():
            calls.append(time.monotonic())
            await asyncio.sleep(.055)
        task = asyncio.create_task(run.periodic("slow", .02, 0, slow))
        await asyncio.sleep(.17)
        run.stop.set()
        await task
        assert 1 <= len(calls) <= 3
        assert run.skipped["slow"] > 0
        assert all(b - a >= .05 for a, b in zip(calls, calls[1:]))
    asyncio.run(scenario())


def test_shutdown_drains_started_job_and_excludes_late_metrics_from_coverage(tmp_path):
    async def scenario():
        run = capacity.CapacityRun(arguments(tmp_path, extra=["--agents", "1", "--require-metrics-coverage"]))
        running, finish = asyncio.Event(), asyncio.Event()
        calls = []
        async def request(session, name, method, path, **kwargs):
            calls.append(name)
            if name == "next-job":
                return 200, {"job": {"job_id": "job", "job_nonce": "nonce", "type": "query-metrics"}}
            if name == "job-event/running":
                running.set()
                await finish.wait()
            return 200, {"ok": True}
        run.request = request
        poll = run.start_task(run.poll(None, None, 0), "poll")
        run.poll_tasks.append(poll)
        await running.wait()
        run.steady_finished_mono = time.monotonic()
        drain = asyncio.create_task(run.drain())
        await asyncio.sleep(.01)
        assert not drain.done()
        finish.set()
        await drain
        assert poll.cancelled()
        assert calls == ["next-job", "job-event/running", "job-event/result"]
        assert run.jobs["query-metrics:success"] == 1
        report = run.report()
        assert report["metrics_acknowledgements"]["agents_seen"] == 0
        assert report["metrics_acknowledgements"]["agents_acknowledged_during_drain"] == ["capacity-unit-00000"]
        assert capacity.validation_failures(report, run.args) == [{"check": "metrics_coverage", "missing_agents": 1}]
    asyncio.run(scenario())


def test_background_workload_exception_is_reported_and_fails_validation(tmp_path):
    async def scenario():
        run = capacity.CapacityRun(arguments(tmp_path))
        async def broken():
            raise RuntimeError("Do not expose arbitrary exception contents")
        run.start_task(broken(), "heartbeat")
        await run.drain()
        report = run.report()
        assert report["background_errors"] == {"heartbeat:RuntimeError": 1}
        assert capacity.validation_failures(report, run.args) == [{"check": "background_errors"}]
    asyncio.run(scenario())


def test_one_broken_ui_route_cannot_be_hidden_by_successful_heartbeats(tmp_path):
    run = capacity.CapacityRun(arguments(tmp_path))
    for _ in range(1000):
        run.stats[("steady", "heartbeat")].add(.01, status=200)
    run.stats[("steady", "ui/hosts")].add(.01, status=500)
    assert capacity.validation_failures(run.report(), run.args) == [
        {"check": "endpoint_error_rate", "phase": "steady", "endpoint": "ui/hosts", "requests": 1, "failures": 1}]


@pytest.mark.parametrize("unsupported", [False, True])
def test_http_workload_signatures_nonce_metrics_ui_and_outputs(tmp_path, unsupported, capsys):
    async def scenario():
        counters = Counter()
        tokens, jobs, events = {}, {}, []
        failure_file = tmp_path / "must-not-exist"
        async def handle(request):
            raw = await request.read()
            path = request.path
            if path == "/agent/register":
                assert request.headers["X-Fleet-Agent-Token"] == "isolated-bootstrap-secret"
                body = json.loads(raw)
                aid = body["agent_id"]
                tokens[aid] = "issued-secret-" + aid
                kinds = ["query-users", "query-metrics"]
                if unsupported:
                    kinds.append("shell-command")
                jobs[aid] = [{"job_id": f"job-{aid}-{i}", "job_nonce": f"nonce-{aid}-{i}", "type": kind,
                              "command": f"touch {failure_file}"} for i, kind in enumerate(kinds)]
                return web.json_response({"ok": True, "agent_token": tokens[aid]})
            if path.startswith("/agent/"):
                aid = request.headers["X-Fleet-Agent-ID"]
                assert request.headers["X-Fleet-Agent-Token"] == tokens[aid]
                timestamp = request.headers["X-Fleet-Agent-Timestamp"]
                message = "\n".join([request.method, request.raw_path, timestamp, hashlib.sha256(raw).hexdigest()])
                expected = hmac.new(hashlib.sha256(tokens[aid].encode()).hexdigest().encode(), message.encode(), hashlib.sha256).hexdigest()
                assert hmac.compare_digest(request.headers["X-Fleet-Agent-Signature"], expected)
                counters[path] += 1
                if path == "/agent/next-job":
                    if jobs[aid]:
                        return web.json_response({"job": jobs[aid].pop(0)})
                    await asyncio.sleep(.08)
                    return web.json_response({"job": None})
                if path == "/agent/inventory/packages":
                    assert len(json.loads(raw)["packages"]) == 10
                if path == "/agent/job-event":
                    event = json.loads(raw)
                    i = int(event["job_id"].rsplit("-", 1)[1])
                    assert event["job_nonce"] == f"nonce-{aid}-{i}"
                    events.append(event)
                    if event["status"] == "success" and i == 1:
                        result = json.loads(event["stdout"])
                        assert result["metrics"]["cpu"]["vcpus"] > 0
                        assert 0 <= result["metrics"]["disk_usage"]["percent_used"] <= 100
                        assert "memory" in result["metrics"]
                    if i == 2 and event["status"] != "running":
                        assert event["status"] == "failed"
                return web.json_response({"ok": True})
            assert request.cookies["fleet_session"] == "isolated-session-secret"
            assert "X-Fleet-Agent-Token" not in request.headers
            assert request.method == "GET"
            if path == "/dashboard/attention":
                assert request.query["include_live"] == "false"
            counters["ui"] += 1
            return web.json_response({"items": []})

        application = web.Application()
        application.router.add_route("*", "/{path:.*}", handle)
        runner = web.AppRunner(application)
        await runner.setup()
        site = web.TCPSite(runner, "127.0.0.1", 0)
        await site.start()
        port = site._server.sockets[0].getsockname()[1]
        try:
            args = arguments(tmp_path, f"http://127.0.0.1:{port}")
            result = await capacity.main_async(args)
        finally:
            await runner.cleanup()
        assert result == int(unsupported)
        report = json.loads(Path(args.json).read_text())
        ready = json.loads(Path(args.ready_file).read_text())
        assert ready["agents"] == ready["initial_inventories"] == 3
        assert report["ready_at"] <= report["ended_at"]
        assert report["steady_seconds"] >= .35
        assert report["metrics_acknowledgements"]["agents_seen"] == 3
        assert report["metrics_acknowledgements"]["agents_missing"] == []
        assert counters["/agent/heartbeat"] >= 9  # Continues while all three long polls wait.
        assert counters["/agent/inventory/packages"] >= 6
        assert counters["ui"] >= len(capacity.UI_PATHS)
        assert report["steady_http_excluding_long_poll"]["failures"] == 0
        assert report["jobs"]["query-users:success"] == 3
        assert report["jobs"]["query-metrics:success"] == 3
        assert bool(report["unsupported_jobs"]) is unsupported
        assert not failure_file.exists()
        for event in events:
            if event["status"] != "running":
                assert any(previous["status"] == "running" and previous["job_id"] == event["job_id"] for previous in events)
        csv_text = Path(args.csv).read_text()
        assert "started_at,finished_at,phase" in csv_text
        assert "issued-secret" not in csv_text + Path(args.json).read_text()
        assert "isolated-session-secret" not in csv_text + Path(args.json).read_text()
    asyncio.run(scenario())
    output = capsys.readouterr().out
    assert "isolated-bootstrap-secret" not in output
    assert "isolated-session-secret" not in output
