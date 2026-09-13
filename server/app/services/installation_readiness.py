"""Read-only final deployment check, invoked locally inside the server container."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import time

from sqlalchemy import func, or_, select

from ..db import SessionLocal
from ..models import Host, HostPackage, HostUser


def inspect_host(db, target: str, address: str, since: datetime) -> dict:
    names = {target, address} - {''}
    matches = db.execute(select(Host).where(or_(
        Host.agent_id.in_(names), Host.hostname.in_(names),
        Host.fqdn.in_(names), Host.ip_address.in_(names),
    ))).scalars().all()
    result = {'target': target, 'ready': False}
    if len(matches) != 1:
        return dict(result, waiting='registration' if not matches else 'ambiguous host identity')
    host = matches[0]
    last_seen = host.last_seen
    if last_seen and last_seen.tzinfo is None:
        last_seen = last_seen.replace(tzinfo=timezone.utc)
    cutoff = max(since.timestamp(), time.time() - 120)
    if not last_seen or last_seen.timestamp() < cutoff:
        return dict(result, waiting='agent heartbeat')
    packages = db.scalar(select(func.count()).select_from(HostPackage).where(
        HostPackage.host_id == host.id, HostPackage.collected_at >= since,
    ))
    users = db.scalar(select(func.count()).select_from(HostUser).where(
        HostUser.host_id == host.id, HostUser.last_seen >= since,
    ))
    if not packages:
        return dict(result, waiting='fresh package inventory')
    if not users:
        return dict(result, waiting='fresh user inventory')
    return dict(result, ready=True, packages=packages, users=users)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host', action='append', required=True, help='target=resolved IPv4')
    parser.add_argument('--since', type=int, required=True)
    parser.add_argument('--timeout', type=int, default=180)
    args = parser.parse_args()
    if not 1 <= args.timeout <= 600:
        parser.error('timeout must be between 1 and 600 seconds')
    targets = [(item.partition('=')[0], item.partition('=')[2]) for item in args.host]
    since = datetime.fromtimestamp(args.since, timezone.utc)
    deadline = time.monotonic() + args.timeout
    previous = None
    while True:
        with SessionLocal() as db:
            results = [inspect_host(db, target, address, since) for target, address in targets]
        message = '\n'.join(
            f"[OK] {item['target']}: connected, {item['packages']} packages, {item['users']} users"
            if item['ready'] else f"[WAIT] {item['target']}: {item['waiting']}"
            for item in results
        )
        if message != previous:
            print(message, flush=True)
            previous = message
        if all(item['ready'] for item in results):
            return 0
        if time.monotonic() >= deadline:
            return 1
        time.sleep(min(3, max(0, deadline - time.monotonic())))


if __name__ == '__main__':
    raise SystemExit(main())
