#!/usr/bin/env python3
"""Update registered agents via existing Master SSH access; no re-enrollment."""
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys


def valid_address(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return bool(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,252}', value))


def target_for(host, inventory, default_user, identity):
    variables = inventory.get('_meta', {}).get('hostvars', {})
    # Match saved inventory by address or hostname, including inventory aliases.
    address = host.get('ip_address') or host.get('fqdn') or host.get('hostname') or ''
    matches = []
    for name, values in variables.items():
        if name in (address, host.get('hostname'), host.get('fqdn')) or values.get('ansible_host') == address:
            matches.append(values)
    if len(matches) > 1 and any(item != matches[0] for item in matches[1:]):
        raise ValueError('Conflicting SSH inventory entries; correct the inventory before retrying')
    values = matches[0] if matches else {}
    address = str(values.get('ansible_host') or address)
    user = str(values.get('ansible_user') or default_user)
    port = str(values.get('ansible_port') or '22')
    key = identity or values.get('ansible_ssh_private_key_file') or values.get('ansible_private_key_file')
    if not valid_address(address) or not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.-]*', user):
        raise ValueError('Invalid or missing SSH address/username')
    if not port.isdigit() or not 1 <= int(port) <= 65535:
        raise ValueError('Invalid SSH port')
    args = ['ssh', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
            '-o', 'ConnectTimeout=10', '-o', 'ConnectionAttempts=1',
            '-o', 'ServerAliveInterval=10', '-o', 'ServerAliveCountMax=3', '-p', port]
    if not key and Path('~/.ssh/fleet_management').expanduser().is_file():
        key = '~/.ssh/fleet_management'
    if key:
        args += ['-i', os.path.expanduser(str(key))]
    args += [f'{user}@{address}']
    return args


def remote(ssh, helper, mode, agent_id, data=None, checksum=None):
    args = ['python3', '-c', helper, mode, agent_id]
    if checksum:
        args.append(checksum)
    command = 'if [ "$(id -u)" = 0 ]; then exec ' + shlex.join(args) + '; else exec sudo -n ' + shlex.join(args) + '; fi'
    result = subprocess.run(ssh + [command], input=data if data is not None else b'', capture_output=True, timeout=150)
    if result.returncode:
        detail = result.stderr.decode(errors='replace').strip()[-1200:]
        raise RuntimeError(detail or 'SSH agent update failed')
    return json.loads(result.stdout)


def update_host(host, inventory, args, artifacts, helper):
    ssh = target_for(host, inventory, args.ssh_user, args.identity)
    agent_id = host['agent_id']
    probe = remote(ssh, helper, 'probe', agent_id)
    artifact = artifacts.get(probe.get('arch'))
    if artifact is None:
        raise RuntimeError('No matching architecture artifact in the new Master')
    data, checksum = artifact
    if probe['sha256'] == checksum and probe['running_sha256'] == checksum:
        return {'status': 'unchanged', 'sha256': checksum}
    return remote(ssh, helper, 'update', agent_id, data, checksum)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--hosts', type=Path, required=True)
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--inventory', type=Path)
    parser.add_argument('--ssh-user', required=True)
    parser.add_argument('--identity')
    parser.add_argument('--workers', type=int, default=4, choices=range(1, 17))
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    hosts = json.loads(args.hosts.read_text())
    inventory = json.loads(args.inventory.read_text()) if args.inventory else {}
    helper = Path(__file__).with_name('update-agent-remote.py').read_text()
    artifacts = {}
    for arch in ('amd64', 'arm64'):
        data = (args.artifacts / f'fleet-agent-{arch}').read_bytes()
        artifacts[arch] = (data, hashlib.sha256(data).hexdigest())
    print(f'Updating {len(hosts)} registered agent(s) using existing SSH keys and sudo rights', flush=True)
    results = []
    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = {executor.submit(update_host, host, inventory, args, artifacts, helper): host for host in hosts}
        for future in as_completed(futures):
            host = futures[future]
            try:
                result = future.result()
            except Exception as error:
                result = {'status': 'failed', 'error': str(error)}
            result['agent_id'] = host['agent_id']
            results.append(result)
            print(f"{host['agent_id']}: {result['status']}" + (f" — {result['error']}" if result.get('error') else ''), flush=True)
    args.report.write_text(json.dumps(results, indent=2) + '\n')
    counts = {status: sum(row['status'] == status for row in results) for status in ('updated', 'unchanged', 'failed')}
    print('Agent update: ' + ', '.join(f'{count} {status}' for status, count in counts.items()), flush=True)
    if counts['failed']:
        print('Master remains installed. Check SSH keys, known_hosts, sudo and connectivity for failed hosts, then rerun install.sh --resume.', flush=True)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
