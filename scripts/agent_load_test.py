#!/usr/bin/env python3
from __future__ import annotations

import argparse
import asyncio
import csv
import hashlib
import hmac
import json
import math
import os
import statistics
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import quote


@dataclass
class EndpointStats:
    durations: list[float] = field(default_factory=list)
    statuses: dict[int, int] = field(default_factory=dict)
    errors: dict[str, int] = field(default_factory=dict)

    def add(self, duration: float, status: int | None = None, error: str | None = None) -> None:
        self.durations.append(duration)
        if status is not None:
            self.statuses[status] = self.statuses.get(status, 0) + 1
        if error:
            self.errors[error] = self.errors.get(error, 0) + 1

    @property
    def total(self) -> int:
        return len(self.durations)

    @property
    def failures(self) -> int:
        bad_statuses = sum(count for status, count in self.statuses.items() if status < 200 or status >= 300)
        return bad_statuses + sum(self.errors.values())


def percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    idx = min(len(ordered) - 1, max(0, math.ceil((pct / 100.0) * len(ordered)) - 1))
    return ordered[idx]


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def body_bytes(payload: Any | None) -> bytes:
    if payload is None:
        return b""
    return json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")


def signed_headers(method: str, target: str, token: str, body: bytes) -> dict[str, str]:
    ts = str(int(time.time()))
    body_digest = hashlib.sha256(body).hexdigest()
    msg = "\n".join([method.upper(), target, ts, body_digest])
    sig = hmac.new(token_hash(token).encode("utf-8"), msg.encode("utf-8"), hashlib.sha256).hexdigest()
    return {
        "X-Fleet-Agent-Timestamp": ts,
        "X-Fleet-Agent-Signature": sig,
    }


def agent_id(prefix: str, idx: int) -> str:
    return f"{prefix}-{idx:05d}"


def register_payload(prefix: str, idx: int) -> dict[str, Any]:
    aid = agent_id(prefix, idx)
    third = 10 + ((idx // 254) % 200)
    fourth = 1 + (idx % 254)
    return {
        "agent_id": aid,
        "hostname": aid,
        "fqdn": f"{aid}.loadtest.local",
        "ip_addresses": [f"10.250.{third}.{fourth}"],
        "os_id": "debian",
        "os_version": "12",
        "kernel": "6.1.0-loadtest",
        "agent_version": "loadtest-0.1",
        "labels": {"env": "loadtest", "batch": prefix},
    }


def packages_payload(prefix: str, idx: int, packages_per_host: int) -> dict[str, Any]:
    packages = [
        {
            "name": f"pkg-{i:03d}",
            "version": f"1.{idx % 23}.{i}",
            "arch": "amd64",
        }
        for i in range(packages_per_host)
    ]
    return {
        "agent_id": agent_id(prefix, idx),
        "collected_at_unix": int(time.time()),
        "manager": "dpkg",
        "packages": packages,
    }


def updates_payload(prefix: str, idx: int, updates_per_host: int) -> dict[str, Any]:
    updates = [
        {
            "name": f"pkg-{i:03d}",
            "installed_version": f"1.{idx % 23}.{i}",
            "candidate_version": f"1.{idx % 23}.{i + 1}",
            "is_security": i % 5 == 0,
        }
        for i in range(updates_per_host)
    ]
    return {
        "agent_id": agent_id(prefix, idx),
        "checked_at_unix": int(time.time()),
        "reboot_required": idx % 97 == 0,
        "updates": updates,
    }


def load_tokens(path: Path | None) -> dict[str, str]:
    if not path or not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise SystemExit(f"Token cache is not an object: {path}")
    return {str(k): str(v) for k, v in data.items() if str(v).strip()}


def save_tokens(path: Path | None, tokens: dict[str, str]) -> None:
    if not path:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as f:
        json.dump(tokens, f, indent=2, sort_keys=True)
    os.replace(tmp, path)


async def pace(index: int, total: int, ramp_up_seconds: float) -> None:
    if ramp_up_seconds <= 0 or total <= 1:
        return
    await asyncio.sleep((index / max(1, total - 1)) * ramp_up_seconds)


async def request_json(
    session: aiohttp.ClientSession,
    *,
    stats: dict[str, EndpointStats],
    name: str,
    method: str,
    base_url: str,
    target: str,
    token: str | None,
    agent: str | None = None,
    payload: Any | None = None,
    sign: bool = False,
) -> tuple[int | None, Any | None]:
    body = body_bytes(payload)
    headers = {"Content-Type": "application/json"}
    if agent:
        headers["X-Fleet-Agent-ID"] = agent
    if token:
        headers["X-Fleet-Agent-Token"] = token
        if sign:
            headers.update(signed_headers(method, target, token, body))

    started = time.perf_counter()
    try:
        async with session.request(method, base_url + target, data=body if payload is not None else None, headers=headers) as resp:
            text = await resp.text()
            elapsed = time.perf_counter() - started
            stats[name].add(elapsed, status=resp.status)
            try:
                return resp.status, json.loads(text) if text else None
            except json.JSONDecodeError:
                return resp.status, text
    except Exception as exc:
        elapsed = time.perf_counter() - started
        stats[name].add(elapsed, error=type(exc).__name__)
        return None, None


async def run_bounded(items: list[int], concurrency: int, worker) -> None:
    sem = asyncio.Semaphore(max(1, concurrency))

    async def one(pos: int, item: int) -> None:
        async with sem:
            await worker(pos, item)

    await asyncio.gather(*(one(pos, item) for pos, item in enumerate(items)))


async def main_async(args: argparse.Namespace) -> int:
    try:
        import aiohttp
    except ModuleNotFoundError as exc:
        raise SystemExit("Missing dependency: install aiohttp or run from the repo backend virtualenv") from exc

    base_url = args.base_url.rstrip("/")
    prefix = args.agent_prefix
    token_cache = Path(args.token_cache) if args.token_cache else None
    tokens = load_tokens(token_cache)
    stats = {
        "register": EndpointStats(),
        "heartbeat": EndpointStats(),
        "packages": EndpointStats(),
        "updates": EndpointStats(),
        "next-job": EndpointStats(),
    }

    timeout = aiohttp.ClientTimeout(total=args.timeout)
    connector = aiohttp.TCPConnector(limit=max(args.concurrency * 2, 100), ttl_dns_cache=300)
    agent_indexes = list(range(args.agents))

    async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
        if not args.skip_register:
            print(f"Registering {args.agents} simulated agents against {base_url} ...", flush=True)

            async def register_one(pos: int, idx: int) -> None:
                await pace(pos, args.agents, args.ramp_up_seconds)
                aid = agent_id(prefix, idx)
                status, data = await request_json(
                    session,
                    stats=stats,
                    name="register",
                    method="POST",
                    base_url=base_url,
                    target="/agent/register",
                    token=args.bootstrap_token,
                    payload=register_payload(prefix, idx),
                )
                if status and 200 <= status < 300 and isinstance(data, dict):
                    issued = str(data.get("agent_token") or "").strip()
                    if issued:
                        tokens[aid] = issued

            await run_bounded(agent_indexes, args.concurrency, register_one)
            save_tokens(token_cache, tokens)

        missing = [agent_id(prefix, idx) for idx in agent_indexes if agent_id(prefix, idx) not in tokens]
        if missing and args.require_per_agent_tokens:
            print(f"Missing per-agent tokens for {len(missing)} agents; first missing: {missing[0]}", file=sys.stderr)
            return 2

        for cycle in range(1, args.cycles + 1):
            print(f"Cycle {cycle}/{args.cycles}: heartbeat {args.agents} agents", flush=True)

            async def heartbeat_one(pos: int, idx: int) -> None:
                await pace(pos, args.agents, args.ramp_up_seconds if cycle == 1 else 0)
                aid = agent_id(prefix, idx)
                target = f"/agent/heartbeat?agent_id={quote(aid)}&agent_version=loadtest-0.1"
                token = tokens.get(aid) or args.bootstrap_token
                await request_json(
                    session,
                    stats=stats,
                    name="heartbeat",
                    method="POST",
                    base_url=base_url,
                    target=target,
                    token=token,
                    agent=aid,
                    sign=aid in tokens,
                )

            await run_bounded(agent_indexes, args.concurrency, heartbeat_one)

            inventory_count = int(args.agents * args.inventory_fraction)
            inventory_indexes = agent_indexes[:inventory_count]
            if inventory_indexes and args.packages_per_host >= 0:
                print(f"Cycle {cycle}/{args.cycles}: package inventory {len(inventory_indexes)} agents", flush=True)

                async def packages_one(_pos: int, idx: int) -> None:
                    aid = agent_id(prefix, idx)
                    token = tokens.get(aid) or args.bootstrap_token
                    await request_json(
                        session,
                        stats=stats,
                        name="packages",
                        method="POST",
                        base_url=base_url,
                        target="/agent/inventory/packages",
                        token=token,
                        agent=aid,
                        payload=packages_payload(prefix, idx, args.packages_per_host),
                        sign=aid in tokens,
                    )

                await run_bounded(inventory_indexes, args.concurrency, packages_one)

            update_count = int(args.agents * args.updates_fraction)
            update_indexes = agent_indexes[:update_count]
            if update_indexes and args.updates_per_host >= 0:
                print(f"Cycle {cycle}/{args.cycles}: update inventory {len(update_indexes)} agents", flush=True)

                async def updates_one(_pos: int, idx: int) -> None:
                    aid = agent_id(prefix, idx)
                    token = tokens.get(aid) or args.bootstrap_token
                    await request_json(
                        session,
                        stats=stats,
                        name="updates",
                        method="POST",
                        base_url=base_url,
                        target="/agent/inventory/package-updates",
                        token=token,
                        agent=aid,
                        payload=updates_payload(prefix, idx, args.updates_per_host),
                        sign=aid in tokens,
                    )

                await run_bounded(update_indexes, args.concurrency, updates_one)

            if args.poll_next_job:
                print(f"Cycle {cycle}/{args.cycles}: next-job poll {args.agents} agents", flush=True)

                async def poll_one(_pos: int, idx: int) -> None:
                    aid = agent_id(prefix, idx)
                    token = tokens.get(aid) or args.bootstrap_token
                    target = f"/agent/next-job?agent_id={quote(aid)}"
                    await request_json(
                        session,
                        stats=stats,
                        name="next-job",
                        method="GET",
                        base_url=base_url,
                        target=target,
                        token=token,
                        agent=aid,
                        sign=aid in tokens,
                    )

                await run_bounded(agent_indexes, args.concurrency, poll_one)

            if cycle < args.cycles and args.cycle_sleep_seconds > 0:
                await asyncio.sleep(args.cycle_sleep_seconds)

    write_summary(stats, args.csv)
    failures = sum(s.failures for s in stats.values())
    total = sum(s.total for s in stats.values())
    error_rate = (failures / total) if total else 0.0
    if error_rate > args.fail_on_error_rate:
        print(f"Error rate {error_rate:.2%} exceeded threshold {args.fail_on_error_rate:.2%}", file=sys.stderr)
        return 1
    return 0


def write_summary(stats: dict[str, EndpointStats], csv_path: str | None) -> None:
    rows: list[dict[str, Any]] = []
    print("\nEndpoint summary")
    print("endpoint,total,failures,statuses,errors,avg_ms,p50_ms,p95_ms,p99_ms,max_ms")
    for name, item in stats.items():
        if not item.total:
            continue
        durations_ms = [v * 1000.0 for v in item.durations]
        row = {
            "endpoint": name,
            "total": item.total,
            "failures": item.failures,
            "statuses": json.dumps(item.statuses, sort_keys=True),
            "errors": json.dumps(item.errors, sort_keys=True),
            "avg_ms": round(statistics.fmean(durations_ms), 2),
            "p50_ms": round(percentile(durations_ms, 50), 2),
            "p95_ms": round(percentile(durations_ms, 95), 2),
            "p99_ms": round(percentile(durations_ms, 99), 2),
            "max_ms": round(max(durations_ms), 2),
        }
        rows.append(row)
        print(
            "{endpoint},{total},{failures},{statuses},{errors},{avg_ms},{p50_ms},{p95_ms},{p99_ms},{max_ms}".format(
                **row
            )
        )

    if csv_path:
        path = Path(csv_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(
                f,
                fieldnames=[
                    "endpoint",
                    "total",
                    "failures",
                    "statuses",
                    "errors",
                    "avg_ms",
                    "p50_ms",
                    "p95_ms",
                    "p99_ms",
                    "max_ms",
                ],
            )
            writer.writeheader()
            writer.writerows(rows)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Simulate many fleet agents against the FastAPI agent API.")
    parser.add_argument("--base-url", required=True, help="Server base URL, e.g. http://127.0.0.1:8000")
    parser.add_argument("--bootstrap-token", default=os.getenv("AGENT_SHARED_TOKEN", ""), help="AGENT_SHARED_TOKEN")
    parser.add_argument("--agents", type=int, default=10000, help="Number of simulated hosts")
    parser.add_argument("--agent-prefix", default=f"loadtest-{int(time.time())}", help="agent_id prefix")
    parser.add_argument("--concurrency", type=int, default=200, help="Maximum concurrent HTTP requests")
    parser.add_argument("--ramp-up-seconds", type=float, default=60.0, help="Spread first wave over this many seconds")
    parser.add_argument("--cycles", type=int, default=1, help="Number of steady-state cycles after registration")
    parser.add_argument("--cycle-sleep-seconds", type=float, default=0.0, help="Sleep between cycles")
    parser.add_argument("--timeout", type=float, default=45.0, help="Per-request timeout in seconds")
    parser.add_argument("--token-cache", default=".loadtest-agent-tokens.json", help="Per-agent token cache path")
    parser.add_argument("--skip-register", action="store_true", help="Use existing token cache and skip registration")
    parser.add_argument("--require-per-agent-tokens", action="store_true", help="Fail if any agent lacks an issued token")
    parser.add_argument("--packages-per-host", type=int, default=25, help="Package rows per inventory request; -1 disables")
    parser.add_argument("--updates-per-host", type=int, default=5, help="Update rows per update inventory request; -1 disables")
    parser.add_argument("--inventory-fraction", type=float, default=1.0, help="Fraction of agents sending package inventory")
    parser.add_argument("--updates-fraction", type=float, default=1.0, help="Fraction of agents sending update inventory")
    parser.add_argument("--poll-next-job", action="store_true", help="Also exercise /agent/next-job")
    parser.add_argument("--csv", help="Write summary CSV")
    parser.add_argument("--fail-on-error-rate", type=float, default=0.01, help="Exit nonzero above this failure ratio")
    args = parser.parse_args()

    if args.agents <= 0:
        parser.error("--agents must be positive")
    if args.concurrency <= 0:
        parser.error("--concurrency must be positive")
    if not 0 <= args.inventory_fraction <= 1:
        parser.error("--inventory-fraction must be between 0 and 1")
    if not 0 <= args.updates_fraction <= 1:
        parser.error("--updates-fraction must be between 0 and 1")
    if not args.bootstrap_token and not args.skip_register:
        parser.error("--bootstrap-token is required unless --skip-register is used")
    return args


def main() -> int:
    return asyncio.run(main_async(parse_args()))


if __name__ == "__main__":
    raise SystemExit(main())
