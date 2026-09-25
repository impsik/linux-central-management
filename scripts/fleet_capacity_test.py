#!/usr/bin/env python3
"""Timed, HTTP-only capacity workload for an explicitly isolated Fleet server.

Creates synthetic hosts. Never runs received commands or accesses a database.
--csv records individual requests; --json contains aggregate results. The steady
measurement interval begins only after registration and initial inventories.
"""
from __future__ import annotations

import argparse
import asyncio
import csv
import json
import math
import ssl
import statistics
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlsplit

if __package__:
    from .agent_load_test import EndpointStats, agent_id, body_bytes, percentile, signed_headers
else:
    from agent_load_test import EndpointStats, agent_id, body_bytes, percentile, signed_headers

UI_PATHS = (
    ("ui/summary", "/dashboard/summary"),
    ("ui/urgent-updates", "/dashboard/urgent-updates?limit=10"),
    ("ui/hosts", "/hosts"),
    ("ui/hosts-updates", "/reports/hosts-updates?only_pending=false&online_only=false&limit=500"),
    ("ui/cve-report", "/reports/cve-high-severity?min_severity=7&limit=200"),
    ("ui/attention", "/dashboard/attention?limit=500&include_live=false"),
    ("ui/auth", "/auth/me"),
)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def secret_file(path: str) -> str:
    value = Path(path).read_text(encoding="utf-8").strip()
    if not value:
        raise ValueError("The credential file is empty")
    return value


def package_seed(path: str | None, count: int) -> list[dict[str, str]]:
    if path:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
        raw = raw.get("packages", []) if isinstance(raw, dict) else raw
    else:
        # Representative Ubuntu names for CVE matching; prefer a real dpkg seed.
        raw = [{"name": name, "version": version, "arch": "amd64"} for name, version in (
            ("openssl", "3.0.13-0ubuntu3"), ("libssl3t64", "3.0.13-0ubuntu3"),
            ("curl", "8.5.0-2ubuntu10"), ("libc6", "2.39-0ubuntu8"),
            ("openssh-server", "1:9.6p1-3ubuntu13"), ("sudo", "1.9.15p5-3ubuntu5"),
            ("systemd", "255.4-1ubuntu8"), ("python3.12", "3.12.3-1ubuntu0.1"),
            ("bash", "5.2.21-2ubuntu4"), ("zlib1g", "1:1.3.dfsg-3.1ubuntu2"),
        )]
    if not isinstance(raw, list):
        raise ValueError("Package seed must be a list or an object containing packages")
    packages = {}
    for item in raw:
        if not isinstance(item, dict) or not item.get("name") or not item.get("version"):
            raise ValueError("Each package seed item needs name and version")
        name = str(item["name"])
        packages[name] = {"name": name, "version": str(item["version"]), "arch": str(item.get("arch") or "amd64")}
    result = list(packages.values())[:count]
    i = 0
    while len(result) < count:
        name = f"fleet-load-package-{i:04d}"
        i += 1
        if name not in packages:
            result.append({"name": name, "version": "1.0.0-1", "arch": "amd64"})
    return result


def registration(prefix: str, idx: int) -> dict[str, Any]:
    aid = agent_id(prefix, idx)
    return {"agent_id": aid, "hostname": aid, "fqdn": f"{aid}.invalid",
            "ip_addresses": [f"10.250.{(idx // 254) % 254}.{1 + idx % 254}"],
            "os_id": "ubuntu", "os_version": "24.04", "kernel": "6.8.0-capacity-test",
            "agent_version": "capacity-test-1", "labels": {"env": "capacity-test", "batch": prefix}}


def metrics_result(idx: int) -> dict[str, Any]:
    memory_total = (4 + idx % 4 * 4) * 1024 ** 3
    memory_percent = 30 + idx % 45
    disk_percent = 20 + idx % 60
    vcpus = 2 + idx % 4 * 2
    load = round(vcpus * (0.08 + (idx % 31) / 100), 2)
    return {"metrics": {
        "cpu": {"vcpus": vcpus, "load_1min": load, "load_5min": round(load * .9, 2), "load_15min": round(load * .8, 2)},
        "memory": {"total_bytes": memory_total, "used_bytes": memory_total * memory_percent // 100,
                   "available_bytes": memory_total * (100 - memory_percent) // 100, "percent_used": memory_percent},
        "disk_usage": {"total_bytes": 80 * 1024 ** 3, "used_bytes": 80 * 1024 ** 3 * disk_percent // 100,
                       "available_bytes": 80 * 1024 ** 3 * (100 - disk_percent) // 100, "percent_used": disk_percent},
        "ip_addresses": [f"10.250.{(idx // 254) % 254}.{1 + idx % 254}"], "uptime_seconds": 86400 + idx * 300,
    }}


def users_result() -> dict[str, Any]:
    return {"users": [
        {"username": "root", "uid": 0, "gid": 0, "home": "/root", "shell": "/bin/bash", "has_sudo": True, "is_locked": True},
        {"username": "fleet-test", "uid": 1000, "gid": 1000, "home": "/home/fleet-test", "shell": "/bin/bash", "has_sudo": False, "is_locked": False},
    ]}


def summarize(item: EndpointStats) -> dict[str, Any]:
    ms = [duration * 1000 for duration in item.durations]
    return {"requests": item.total, "failures": item.failures, "statuses": item.statuses, "errors": item.errors,
            "avg_ms": round(statistics.fmean(ms), 3) if ms else 0,
            **{f"p{p}_ms": round(percentile(ms, p), 3) for p in (50, 95, 99)},
            "max_ms": round(max(ms), 3) if ms else 0}


class CapacityRun:
    def __init__(self, args):
        self.args = args
        self.packages = package_seed(args.package_seed_file, args.packages_per_host)
        self.tokens: dict[str, str] = {}
        self.stats = defaultdict(EndpointStats)
        self.pacing = defaultdict(EndpointStats)
        self.skipped = Counter()
        self.cancelled = Counter()
        self.jobs = Counter()
        self.unsupported = Counter()
        self.metrics_completed: dict[str, float] = {}
        self.metrics_drained: dict[str, float] = {}
        self.background_errors = Counter()
        self.observations = []
        self.phase = "warmup"
        self.started_at = utc_now()
        self.started_mono = time.monotonic()
        self.ready_at = None
        self.ready_mono = None
        self.ended_at = None
        self.steady_finished_mono = None
        self.stop = asyncio.Event()
        self.tasks = []
        self.poll_tasks = []
        self.initial_inventory = {}

    def start_task(self, coroutine, kind):
        task = asyncio.create_task(coroutine)
        self.tasks.append(task)
        def finished(done):
            if not done.cancelled() and done.exception() is not None:
                self.background_errors[f"{kind}:{type(done.exception()).__name__}"] += 1
                self.stop.set()
        task.add_done_callback(finished)
        return task

    async def drain(self):
        self.stop.set()
        for task in self.poll_tasks:
            task.cancel()
        # Poll cancellation interrupts the idle GET only. Shielded job handlers,
        # periodic writes and UI requests finish before their sessions close.
        await asyncio.gather(*self.tasks, return_exceptions=True)

    async def wait(self, seconds: float) -> bool:
        if self.stop.is_set():
            return False
        try:
            await asyncio.wait_for(self.stop.wait(), timeout=max(.001, seconds))
            return False
        except asyncio.TimeoutError:
            return True

    async def request(self, session, name, method, target, *, idx=None, payload=None, bootstrap=None):
        body = body_bytes(payload)
        headers = {"Content-Type": "application/json"}
        aid = agent_id(self.args.agent_prefix, idx) if idx is not None else ""
        token = bootstrap or self.tokens.get(aid)
        if token:
            headers["X-Fleet-Agent-Token"] = token
            if not bootstrap:
                headers["X-Fleet-Agent-ID"] = aid
                headers.update(signed_headers(method, target, token, body))
        started = time.monotonic()
        started_at, phase = utc_now(), self.phase
        status, data, error = None, None, None
        try:
            async with session.request(method, self.args.base_url + target,
                                       data=body if payload is not None else None,
                                       headers=headers, allow_redirects=False) as response:
                status = response.status
                text = await response.text()
                if text:
                    try:
                        data = json.loads(text)
                    except json.JSONDecodeError:
                        if 200 <= status < 300:
                            error = "InvalidJSON"
        except asyncio.CancelledError:
            self.cancelled[name] += 1
            raise
        except Exception as exc:
            # Deliberately omit URLs, response bodies and credentials from errors.
            error = type(exc).__name__
        elapsed = time.monotonic() - started
        self.stats[(phase, name)].add(elapsed, status=status, error=error)
        self.observations.append({"started_at": started_at, "finished_at": utc_now(), "phase": phase,
                                  "elapsed_from_start_s": round(started - self.started_mono, 6),
                                  "endpoint": name, "agent_id": aid, "latency_ms": round(elapsed * 1000, 3),
                                  "status": status, "error": error or "", "expected_long_poll": name == "next-job"})
        return status, data

    def inventory_payload(self, idx):
        return {"agent_id": agent_id(self.args.agent_prefix, idx), "collected_at_unix": int(time.time()),
                "manager": "dpkg", "packages": self.packages}

    def updates_payload(self, idx):
        updates = [{"name": package["name"], "installed_version": package["version"],
                    "candidate_version": package["version"] + "+capacity1", "is_security": i % 5 == 0}
                   for i, package in enumerate(self.packages[:self.args.updates_per_host])]
        return {"agent_id": agent_id(self.args.agent_prefix, idx), "checked_at_unix": int(time.time()),
                "reboot_required": idx % 97 == 0, "updates": updates}

    async def inventory(self, session, idx):
        package_status, _ = await self.request(session, "packages", "POST", "/agent/inventory/packages", idx=idx,
                                               payload=self.inventory_payload(idx))
        update_status, _ = await self.request(session, "updates", "POST", "/agent/inventory/package-updates", idx=idx,
                                              payload=self.updates_payload(idx))
        return package_status is not None and 200 <= package_status < 300 and update_status is not None and 200 <= update_status < 300

    async def periodic(self, name, interval, offset, operation, first_result=None):
        scheduled = time.monotonic() + offset
        try:
            while not self.stop.is_set():
                if not await self.wait(scheduled - time.monotonic()):
                    break
                self.pacing[name].add(max(0, time.monotonic() - scheduled))
                result = await operation()
                if first_result is not None and not first_result.done():
                    first_result.set_result(result)
                scheduled += interval
                if scheduled < time.monotonic():
                    missed = math.floor((time.monotonic() - scheduled) / interval) + 1
                    self.skipped[name] += missed
                    scheduled += missed * interval
        finally:
            if first_result is not None and not first_result.done():
                first_result.set_result(False)

    async def handle_job(self, session, idx, job):
        kind = str(job.get("type") or "unknown")[:128]
        job_id = str(job.get("job_id") or "")
        nonce = str(job.get("job_nonce") or "")
        if not job_id or not nonce:
            self.jobs["malformed_missing_id_or_nonce"] += 1
            return
        base = {"agent_id": agent_id(self.args.agent_prefix, idx), "job_id": job_id, "job_nonce": nonce}
        status, _ = await self.request(session, "job-event/running", "POST", "/agent/job-event", idx=idx,
                                       payload={**base, "status": "running"})
        if status is None or not 200 <= status < 300:
            self.jobs["start_rejected"] += 1
            return
        ok, result = True, {}
        if kind == "query-metrics":
            result = metrics_result(idx)
        elif kind == "query-users":
            result = users_result()
        elif kind == "query-pkg-updates":
            result = {**self.updates_payload(idx), "checked_at": utc_now()}
        elif kind == "inventory-now":
            ok = await self.inventory(session, idx)
            result = {"package_count": len(self.packages)}
        else:
            ok = False
            self.unsupported[kind] += 1
        payload = {**base, "status": "success" if ok else "failed", "exit_code": 0 if ok else 64,
                   "stdout": json.dumps(result, separators=(",", ":")) if ok else "",
                   "error": None if ok else "Capacity simulator rejects unsupported operations or failed inventory; no commands executed."}
        status, _ = await self.request(session, "job-event/result", "POST", "/agent/job-event", idx=idx, payload=payload)
        if status is not None and 200 <= status < 300:
            self.jobs[f"{kind}:{'success' if ok else 'failed'}"] += 1
            if kind == "query-metrics" and ok:
                completed = self.metrics_completed if self.steady_finished_mono is None else self.metrics_drained
                completed[base["agent_id"]] = time.monotonic()
        else:
            self.jobs["result_rejected"] += 1

    async def poll(self, poll_session, write_session, idx):
        if not await self.wait((idx / self.args.agents) * self.args.poll_sleep_seconds):
            return
        aid = agent_id(self.args.agent_prefix, idx)
        while not self.stop.is_set():
            status, data = await self.request(poll_session, "next-job", "GET", f"/agent/next-job?agent_id={quote(aid)}", idx=idx)
            if status == 200 and isinstance(data, dict) and isinstance(data.get("job"), dict):
                handler = self.start_task(self.handle_job(write_session, idx, data["job"]), "job-handler")
                await asyncio.shield(handler)
            if not await self.wait(self.args.poll_sleep_seconds):
                break

    async def ui_stream(self, session, number):
        async def probe():
            for name, path in UI_PATHS:
                if self.stop.is_set():
                    break
                await self.request(session, name, "GET", path)
        await self.periodic("ui-round", self.args.ui_interval_seconds,
                            number / self.args.ui_clients * self.args.ui_interval_seconds, probe)

    async def execute(self):
        import aiohttp
        if self.args.ready_file:
            Path(self.args.ready_file).unlink(missing_ok=True)
        bootstrap = secret_file(self.args.bootstrap_token_file)
        cookies = json.loads(secret_file(self.args.ui_cookie_file)) if self.args.ui_cookie_file else {}
        if not isinstance(cookies, dict) or any(not isinstance(v, str) for v in cookies.values()):
            raise ValueError("UI cookie file must be a JSON object mapping cookie names to strings")
        tls = ssl.create_default_context(cafile=self.args.ca_file) if self.args.ca_file else True
        # Idle long polls MUST NOT occupy the sockets used by heartbeats or probes.
        async with (
            aiohttp.ClientSession(connector=aiohttp.TCPConnector(limit=self.args.write_concurrency, ssl=tls),
                                  timeout=aiohttp.ClientTimeout(total=self.args.request_timeout_seconds)) as writes,
            aiohttp.ClientSession(connector=aiohttp.TCPConnector(limit=self.args.agents + 8, ssl=tls),
                                  timeout=aiohttp.ClientTimeout(total=self.args.poll_timeout_seconds + 10)) as polls,
            aiohttp.ClientSession(connector=aiohttp.TCPConnector(limit=max(1, self.args.ui_clients), ssl=tls),
                                  timeout=aiohttp.ClientTimeout(total=self.args.request_timeout_seconds),
                                  cookies=cookies, cookie_jar=aiohttp.CookieJar(unsafe=True)) as ui,
        ):
            registration_start = time.monotonic()
            async def register(idx):
                delay = idx / max(1, self.args.agents - 1) * self.args.ramp_up_seconds
                if not await self.wait(registration_start + delay - time.monotonic()):
                    return False
                status, data = await self.request(writes, "register", "POST", "/agent/register", bootstrap=bootstrap,
                                                 payload=registration(self.args.agent_prefix, idx))
                if status != 200 or not isinstance(data, dict) or not data.get("agent_token"):
                    return False
                aid = agent_id(self.args.agent_prefix, idx)
                self.tokens[aid] = str(data["agent_token"])
                target = f"/agent/heartbeat?agent_id={quote(aid)}&agent_version=capacity-test-1"
                future = asyncio.get_running_loop().create_future()
                self.initial_inventory[idx] = future
                self.start_task(self.periodic("heartbeat", self.args.heartbeat_seconds,
                    idx / self.args.agents * self.args.heartbeat_seconds,
                    lambda: self.request(writes, "heartbeat", "POST", target, idx=idx)), "heartbeat")
                self.start_task(self.periodic("inventory", self.args.inventory_seconds,
                    idx / self.args.agents * self.args.inventory_stagger_seconds,
                    lambda: self.inventory(writes, idx), future), "inventory")
                task = self.start_task(self.poll(polls, writes, idx), "poll")
                self.poll_tasks.append(task)
                return True
            try:
                registered = await asyncio.gather(*(register(idx) for idx in range(self.args.agents)))
                if not all(registered):
                    raise RuntimeError(f"Registration failed for {registered.count(False)} synthetic hosts")
                initial = await asyncio.gather(*self.initial_inventory.values())
                if not all(initial):
                    raise RuntimeError(f"Initial inventory failed for {initial.count(False)} synthetic hosts")
                self.ready_at, self.ready_mono = utc_now(), time.monotonic()
                self.phase = "steady"
                if self.args.ready_file:
                    path = Path(self.args.ready_file)
                    path.parent.mkdir(parents=True, exist_ok=True)
                    temporary = path.with_name(path.name + ".tmp")
                    temporary.write_text(json.dumps({"ready_at": self.ready_at, "agents": len(self.tokens),
                                               "initial_inventories": len(initial), "agent_prefix": self.args.agent_prefix}), encoding="utf-8")
                    temporary.replace(path)
                print(f"Ready: {len(self.tokens)} agents with initial inventory; steady workload {self.args.duration_seconds:g}s", flush=True)
                if cookies:
                    for i in range(self.args.ui_clients):
                        self.start_task(self.ui_stream(ui, i), "ui")
                deadline = self.ready_mono + self.args.duration_seconds
                while time.monotonic() < deadline:
                    if not await self.wait(min(30, deadline - time.monotonic())):
                        raise RuntimeError("A background workload stopped unexpectedly")
                    steady_stats = [(name, stats) for (phase, name), stats in self.stats.items() if phase == "steady"]
                    failures = sum(stats.failures for _, stats in steady_stats)
                    ui_p95 = [percentile(stats.durations, 95) * 1000 for name, stats in steady_stats
                              if name.startswith("ui/") and stats.durations]
                    ui_status = f"{max(ui_p95):.1f}ms" if ui_p95 else "n/a"
                    print(f"Progress: {max(0, time.monotonic() - self.ready_mono):.0f}s steady; "
                          f"metrics acknowledged by {len(self.metrics_completed)}/{self.args.agents} hosts; "
                          f"steady HTTP failures: {failures}; max UI endpoint p95: {ui_status}", flush=True)
            finally:
                self.steady_finished_mono, self.ended_at = time.monotonic(), utc_now()
                self.phase = "drain"
                await self.drain()

    def report(self, run_error=None):
        end = self.steady_finished_mono or time.monotonic()
        ages = [max(0, end - last) for last in self.metrics_completed.values()]
        missing = [agent_id(self.args.agent_prefix, i) for i in range(self.args.agents)
                   if agent_id(self.args.agent_prefix, i) not in self.metrics_completed]
        endpoints = [{"phase": phase, "endpoint": name, "expected_long_poll": name == "next-job", **summarize(stats)}
                     for (phase, name), stats in sorted(self.stats.items())]
        fast = EndpointStats()
        for (phase, name), stats in self.stats.items():
            if phase == "steady" and name != "next-job":
                fast.durations.extend(stats.durations)
                fast.statuses = dict(Counter(fast.statuses) + Counter(stats.statuses))
                fast.errors = dict(Counter(fast.errors) + Counter(stats.errors))
        return {"schema_version": 1, "started_at": self.started_at, "ready_at": self.ready_at, "ended_at": self.ended_at,
                "warmup_seconds": round((self.ready_mono or end) - self.started_mono, 3),
                "steady_seconds": round(end - self.ready_mono, 3) if self.ready_mono else 0,
                "drain_seconds": round(time.monotonic() - end, 3), "run_error": run_error,
                "workload": {"agents": self.args.agents, "registered_agents": len(self.tokens), "agent_prefix": self.args.agent_prefix,
                    "packages_per_host": len(self.packages), "updates_per_host": min(len(self.packages), self.args.updates_per_host),
                    "heartbeat_seconds": self.args.heartbeat_seconds,
                    "inventory_seconds": self.args.inventory_seconds, "inventory_stagger_seconds": self.args.inventory_stagger_seconds,
                    "expected_long_poll_seconds": self.args.poll_timeout_seconds, "poll_sleep_seconds": self.args.poll_sleep_seconds,
                    "ui_streams": self.args.ui_clients if self.args.ui_cookie_file else 0, "ui_shared_session": bool(self.args.ui_cookie_file),
                    "ui_round_interval_seconds": self.args.ui_interval_seconds, "os": "Ubuntu 24.04", "seed_file_used": bool(self.args.package_seed_file)},
                "steady_http_excluding_long_poll": summarize(fast), "endpoints": endpoints,
                "pacing": {name: {"scheduling_lateness": summarize(stats), "missed_intervals": self.skipped[name]} for name, stats in self.pacing.items()},
                "cancelled_in_flight_at_shutdown": dict(self.cancelled), "jobs": dict(self.jobs), "unsupported_jobs": dict(self.unsupported),
                "background_errors": dict(self.background_errors),
                "metrics_acknowledgements": {"agents_seen": len(self.metrics_completed), "agents_missing": missing,
                    "fresh_within_300s": sum(age <= 300 for age in ages), "max_age_seconds": round(max(ages), 3) if ages else None,
                    "p95_age_seconds": round(percentile(ages, 95), 3) if ages else None,
                    "agents_acknowledged_during_drain": sorted(self.metrics_drained),
                    "note": "Accepted query-metrics success events before the measurement deadline; verify persisted snapshot coverage independently."}}


def validation_failures(result, args):
    failures = []
    for key in ("run_error", "background_errors", "unsupported_jobs"):
        if result[key]:
            failures.append({"check": key})
    if result["jobs"].get("malformed_missing_id_or_nonce"):
        failures.append({"check": "malformed_jobs"})
    if args.require_metrics_coverage and result["metrics_acknowledgements"]["agents_missing"]:
        failures.append({"check": "metrics_coverage", "missing_agents": len(result["metrics_acknowledgements"]["agents_missing"])})
    # A failing UI route must not be hidden by thousands of good heartbeats.
    for endpoint in result["endpoints"]:
        if endpoint["failures"] / max(1, endpoint["requests"]) > args.fail_on_error_rate:
            failures.append({"check": "endpoint_error_rate", "phase": endpoint["phase"], "endpoint": endpoint["endpoint"],
                             "requests": endpoint["requests"], "failures": endpoint["failures"]})
    return failures


def parse_args(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--base-url", required=True, help="Explicit URL of an ISOLATED test server")
    p.add_argument("--confirm-isolated", action="store_true", required=True, help="Acknowledge this creates synthetic hosts and inventories")
    p.add_argument("--bootstrap-token-file", required=True)
    p.add_argument("--ui-cookie-file", help="JSON object of cookie names/values from a normal test login; never printed")
    p.add_argument("--package-seed-file", help="JSON package list captured from Ubuntu 24.04, padded/truncated to requested size")
    p.add_argument("--ca-file", help="Trusted CA bundle for an HTTPS test server")
    p.add_argument("--agents", type=int, default=100)
    p.add_argument("--agent-prefix", default=f"capacity-{int(time.time())}")
    p.add_argument("--packages-per-host", type=int, default=850)
    p.add_argument("--updates-per-host", type=int, default=25)
    p.add_argument("--duration-seconds", type=float, default=420, help="Steady duration AFTER all initial inventories succeed")
    p.add_argument("--ramp-up-seconds", type=float, default=20)
    p.add_argument("--inventory-stagger-seconds", type=float, default=60)
    p.add_argument("--heartbeat-seconds", type=float, default=5)
    p.add_argument("--inventory-seconds", type=float, default=300)
    p.add_argument("--poll-timeout-seconds", type=float, default=25, help="Expected server long-poll duration; configure server to match")
    p.add_argument("--poll-sleep-seconds", type=float, default=2)
    p.add_argument("--write-concurrency", type=int, default=64)
    p.add_argument("--request-timeout-seconds", type=float, default=40)
    p.add_argument("--ui-clients", type=int, default=3)
    p.add_argument("--ui-interval-seconds", type=float, default=15)
    p.add_argument("--ready-file")
    p.add_argument("--json", required=True, help="Aggregate report path; includes warmup and steady endpoint percentiles")
    p.add_argument("--csv", required=True, help="Individual request observations with timestamps for sync-window analysis")
    p.add_argument("--fail-on-error-rate", type=float, default=.01, help="Fail if ANY endpoint/phase exceeds this failure fraction")
    p.add_argument("--require-metrics-coverage", action="store_true", help="Fail unless every host acknowledges metrics before the measurement deadline")
    args = p.parse_args(argv)
    parsed = urlsplit(args.base_url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path not in ("", "/"):
        p.error("--base-url must be an HTTP(S) origin without credentials, query, or path")
    args.base_url = args.base_url.rstrip("/")
    for name in ("agents", "packages_per_host", "duration_seconds", "heartbeat_seconds", "inventory_seconds", "poll_timeout_seconds", "poll_sleep_seconds", "write_concurrency", "request_timeout_seconds", "ui_clients", "ui_interval_seconds"):
        if getattr(args, name) <= 0:
            p.error(f"--{name.replace('_', '-')} must be positive")
    for name in ("ramp_up_seconds", "inventory_stagger_seconds", "updates_per_host"):
        if getattr(args, name) < 0:
            p.error(f"--{name.replace('_', '-')} cannot be negative")
    if not 0 <= args.fail_on_error_rate <= 1:
        p.error("--fail-on-error-rate must be between 0 and 1")
    if not args.agent_prefix or any(not (c.isalnum() or c in "-_") for c in args.agent_prefix):
        p.error("--agent-prefix must contain only letters, digits, hyphens, or underscores")
    return args


async def main_async(args):
    run = CapacityRun(args)
    error = None
    print(f"ISOLATED CAPACITY TEST: creates {args.agents} synthetic hosts at {args.base_url}", flush=True)
    try:
        await run.execute()
    except Exception as exc:
        error = type(exc).__name__  # Never dump request headers or secret file contents.
        print(f"Run failed: {error}", flush=True)
    result = run.report(error)
    result["validation_failures"] = validation_failures(result, args)
    for path in (args.json, args.csv):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(args.json).write_text(json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")
    fields = ["started_at", "finished_at", "phase", "elapsed_from_start_s", "endpoint", "agent_id", "latency_ms", "status", "error", "expected_long_poll"]
    with Path(args.csv).open("w", encoding="utf-8", newline="") as output:
        writer = csv.DictWriter(output, fieldnames=fields)
        writer.writeheader()
        writer.writerows(run.observations)
    total = sum(stats.total for stats in run.stats.values())
    failures = sum(stats.failures for stats in run.stats.values())
    print(f"Finished: {total} requests, {failures} HTTP failures, {len(run.metrics_completed)}/{args.agents} hosts acknowledged metrics", flush=True)
    return int(bool(result["validation_failures"]))


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main_async(parse_args())))
