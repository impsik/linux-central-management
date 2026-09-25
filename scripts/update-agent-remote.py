#!/usr/bin/env python3
"""Binary-only agent replacement, invoked over the Master's authenticated SSH.

Never writes agent identity, tokens, environment, certificates or systemd units.
All helpers are importable so tests can replace OS interaction.
"""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import platform
import signal
import subprocess
import sys
import tempfile
import time

BINARY = Path('/opt/fleet-agent/fleet-agent')
SERVICE = 'fleet-agent.service'


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def command(*args):
    return subprocess.check_output(args, text=True, timeout=20).strip()


def running_pid():
    pid = command('systemctl', 'show', SERVICE, '--property=MainPID', '--value')
    if not pid.isdigit() or int(pid) <= 0:
        raise RuntimeError('Agent service has no running process')
    return pid


def verify_identity(expected_id):
    if os.geteuid() != 0:
        raise RuntimeError('Passwordless sudo/root access is required')
    start = command('systemctl', 'show', SERVICE, '--property=ExecStart', '--value')
    if 'path=/opt/fleet-agent/fleet-agent ' not in start:
        raise RuntimeError('Unexpected agent executable; custom installation left unchanged')
    if command('systemctl', 'is-active', SERVICE) != 'active':
        raise RuntimeError('Agent service is inactive; left unchanged')
    pid = running_pid()
    env = dict(entry.split(b'=', 1) for entry in Path('/proc', pid, 'environ').read_bytes().split(b'\0') if b'=' in entry)
    actual = env.get(b'FLEET_AGENT_ID', b'srv-001').decode()
    if actual != expected_id:
        raise RuntimeError('Agent identity does not match the Master inventory; left unchanged')
    if BINARY.is_symlink() or not BINARY.is_file():
        raise RuntimeError('Agent binary must be a regular file')
    return pid


def configuration_hashes():
    paths = [Path('/etc/fleet-agent.env'), Path('/etc/systemd/system/fleet-agent.service'),
             Path('/var/lib/fleet-agent/agent-token')]
    for folder in ('/etc/fleet-agent', '/etc/systemd/system/fleet-agent.service.d'):
        paths.extend(sorted(Path(folder).rglob('*')))
    return {str(path): sha256(path.read_bytes()) for path in paths if path.is_file()}


def running_binary(pid):
    return Path('/proc', pid, 'exe').read_bytes()


def replace_binary(data, destination=None):
    destination = destination or BINARY
    fd, name = tempfile.mkstemp(prefix='.fleet-agent-update-', dir=destination.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(name, 0o755)
        os.replace(name, destination)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def verify_running(expected_hash):
    # A process appearing for an instant is not sufficient: reject restart loops.
    stable_pid = None
    stable = 0
    for _ in range(15):
        try:
            pid = running_pid()
            active = command('systemctl', 'is-active', SERVICE) == 'active'
            matches = sha256(Path('/proc', pid, 'exe').read_bytes()) == expected_hash
            stable = stable + 1 if active and matches and pid == stable_pid else 0
            stable_pid = pid
            if stable >= 3:
                return
        except (OSError, RuntimeError, subprocess.SubprocessError):
            stable = 0
        time.sleep(1)
    raise RuntimeError('Updated agent did not remain active with the expected binary')


def update(expected_id, data, expected_hash):
    pid = verify_identity(expected_id)
    if not data or sha256(data) != expected_hash:
        raise RuntimeError('Agent artifact checksum mismatch')
    # The file on disk may already be a failed replacement while /proc still
    # refers to the last working executable. Roll back to the running image.
    old = running_binary(pid)
    before = configuration_hashes()
    backup = BINARY.with_name('fleet-agent.previous')
    # Keep one previous binary, avoiding unbounded accumulation across releases.
    if backup.is_symlink():
        raise RuntimeError('Unexpected backup symlink; left unchanged')
    replace_binary(old, backup)
    try:
        replace_binary(data)
        subprocess.run(['systemctl', 'restart', SERVICE], check=True, timeout=30)
        verify_running(expected_hash)
        if configuration_hashes() != before:
            raise RuntimeError('Agent configuration changed during the update')
    except BaseException as exc:
        try:
            replace_binary(old)
            subprocess.run(['systemctl', 'restart', SERVICE], check=True, timeout=30)
            verify_running(sha256(old))
        except BaseException as rollback_error:
            raise RuntimeError('Update failed and rollback could not be verified; inspect the node') from rollback_error
        raise RuntimeError(f'Update failed ({exc}); previous binary restored and running') from exc
    return {'status': 'updated', 'sha256': expected_hash}


def dispatch():
    def interrupted(signum, frame):
        raise RuntimeError('Update interrupted')
    for signum in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
        signal.signal(signum, interrupted)
    mode, expected_id = sys.argv[1:3]
    if mode == 'probe':
        pid = verify_identity(expected_id)
        arch = {'x86_64': 'amd64', 'aarch64': 'arm64'}.get(platform.machine())
        if arch is None:
            raise RuntimeError('Unsupported architecture; only amd64 and arm64 are built')
        result = {'arch': arch, 'sha256': sha256(BINARY.read_bytes()),
                  'running_sha256': sha256(Path('/proc', pid, 'exe').read_bytes())}
    elif mode == 'update':
        result = update(expected_id, sys.stdin.buffer.read(100 * 1024 * 1024), sys.argv[3])
    else:
        raise RuntimeError('Invalid update mode')
    print(json.dumps(result))


def main():
    # Avoid two installer runs replacing/rolling back the same node at once.
    with open('/run/fleet-agent-update.lock', 'a') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise RuntimeError('Another agent update is running; retry later') from exc
        dispatch()


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
