"""Exercise updates without SSH, Docker, root or changes to a real agent."""
import importlib.util
import json
from pathlib import Path
import subprocess
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[2]


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts' / f'{name}.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def remote(tmp_path, monkeypatch):
    module = load('update-agent-remote')
    module.BINARY = tmp_path / 'fleet-agent'
    module.BINARY.write_bytes(b'old executable')
    module.BINARY.chmod(0o755)
    monkeypatch.setattr(module, 'verify_identity', lambda expected: '123')
    monkeypatch.setattr(module, 'running_binary', lambda pid: b'old executable')
    monkeypatch.setattr(module, 'configuration_hashes', lambda: {'env': 'unchanged'})
    monkeypatch.setattr(module.subprocess, 'run', lambda *a, **kw: None)
    monkeypatch.setattr(module, 'verify_running', lambda expected: None)
    return module


def test_binary_update_preserves_previous_binary_and_configuration(remote):
    new = b'new executable, same release number'
    result = remote.update('node-1', new, remote.sha256(new))
    assert result['status'] == 'updated'
    assert remote.BINARY.read_bytes() == new
    assert remote.BINARY.with_name('fleet-agent.previous').read_bytes() == b'old executable'
    assert remote.BINARY.stat().st_mode & 0o777 == 0o755
    assert not list(remote.BINARY.parent.glob('.fleet-agent-update-*'))


def test_wrong_artifact_checksum_does_not_modify_node(remote):
    with pytest.raises(RuntimeError, match='checksum mismatch'):
        remote.update('node-1', b'wrong', 'incorrect')
    assert remote.BINARY.read_bytes() == b'old executable'
    assert not remote.BINARY.with_name('fleet-agent.previous').exists()


def test_wrong_node_identity_prevents_any_change(remote, monkeypatch):
    def reject(expected):
        raise RuntimeError('identity mismatch')
    monkeypatch.setattr(remote, 'verify_identity', reject)
    with pytest.raises(RuntimeError, match='identity mismatch'):
        remote.update('wrong-node', b'new', remote.sha256(b'new'))
    assert remote.BINARY.read_bytes() == b'old executable'


def test_failed_new_agent_is_rolled_back(remote, monkeypatch):
    checks = []
    def verify(checksum):
        checks.append(checksum)
        if checksum == remote.sha256(b'broken'):
            raise RuntimeError('new process crashed')
    monkeypatch.setattr(remote, 'verify_running', verify)
    with pytest.raises(RuntimeError, match='previous binary restored and running'):
        remote.update('node-1', b'broken', remote.sha256(b'broken'))
    assert remote.BINARY.read_bytes() == b'old executable'
    assert checks == [remote.sha256(b'broken'), remote.sha256(b'old executable')]


def test_rollback_failure_is_not_reported_as_restored(remote, monkeypatch):
    monkeypatch.setattr(remote, 'verify_running', lambda _: (_ for _ in ()).throw(RuntimeError('service failed')))
    with pytest.raises(RuntimeError, match='rollback could not be verified'):
        remote.update('node-1', b'broken', remote.sha256(b'broken'))


def test_existing_binary_but_old_running_process_is_restarted(remote, monkeypatch):
    calls = []
    monkeypatch.setattr(remote.subprocess, 'run', lambda *a, **kw: calls.append(a))
    remote.update('node-1', b'old executable', remote.sha256(b'old executable'))
    assert calls == [(['systemctl', 'restart', 'fleet-agent.service'],)]


def test_saved_ssh_inventory_and_ipv6_are_supported():
    updater = load('update-agents')
    inventory = {'_meta': {'hostvars': {'node-1': {'ansible_host': '2001:db8::1', 'ansible_user': 'operator', 'ansible_port': 2222}}}}
    args = updater.target_for({'hostname': 'node-1', 'ip_address': '192.0.2.1'}, inventory, 'imre', None)
    assert args[-1] == 'operator@2001:db8::1'
    assert args[args.index('-p') + 1] == '2222'
    assert 'StrictHostKeyChecking=yes' in args
    assert 'BatchMode=yes' in args


@pytest.mark.parametrize('address', ['-oProxyCommand=evil', 'a;touch /tmp/evil', '', 'host\nother'])
def test_untrusted_inventory_address_is_rejected(address):
    updater = load('update-agents')
    with pytest.raises(ValueError):
        updater.target_for({'hostname': address}, {}, 'imre', None)


def test_matching_disk_and_running_hash_skip_upload(monkeypatch):
    updater = load('update-agents')
    calls = []
    def probe(*args):
        calls.append(args)
        return {'arch': 'arm64', 'sha256': 'same', 'running_sha256': 'same'}
    monkeypatch.setattr(updater, 'remote', probe)
    result = updater.update_host({'agent_id': 'id', 'hostname': 'node'}, {},
        SimpleNamespace(ssh_user='imre', identity=None), {'arm64': (b'new', 'same')}, 'helper')
    assert result['status'] == 'unchanged'
    assert len(calls) == 1


def test_installer_agent_stage_exports_registered_hosts_and_current_build(tmp_path):
    functions = (ROOT / 'install.sh').read_text().rsplit('\nmain "$@"', 1)[0]
    script = tmp_path / 'functions.sh'
    script.write_text(functions)
    app = tmp_path / 'app'
    (app / 'deploy/docker').mkdir(parents=True)
    (app / 'scripts').mkdir()
    (app / 'scripts/update-agents.py').write_text('import sys; print("UPDATE_ARGS", *sys.argv[1:])')
    result = subprocess.run(['sh', '-c', '''
. "$1"
APP_DIR="$2"
root_env="$2/.env"
record_install_stage() { printf 'stage:%s\\n' "$1"; }
docker_compose() {
 case "$*" in
  *'python -c'*) printf '[{"agent_id":"node-id","hostname":"node"}]' ;;
  *fleet-agent-amd64*) printf amd64 ;;
  *fleet-agent-arm64*) printf arm64 ;;
  *) return 9 ;;
 esac
}
ANSIBLE_USER=imre
update_existing_agents
''', 'sh', str(script), str(app)], capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
    assert 'stage:agent-update' in result.stdout
    assert '--ssh-user imre' in result.stdout
    assert '--report' in result.stdout


def test_updater_continues_after_one_host_fails_and_reports_it(tmp_path, monkeypatch):
    updater = load('update-agents')
    hosts = tmp_path / 'hosts.json'
    hosts.write_text(json.dumps([{'agent_id': 'ok'}, {'agent_id': 'offline'}]))
    for arch in ('amd64', 'arm64'):
        (tmp_path / f'fleet-agent-{arch}').write_bytes(b'new')
    report = tmp_path / 'results.json'
    monkeypatch.setattr(updater.sys, 'argv', ['update-agents.py', '--hosts', str(hosts), '--artifacts', str(tmp_path), '--ssh-user', 'imre', '--report', str(report)])
    def update(host, *args):
        if host['agent_id'] == 'offline':
            raise RuntimeError('SSH timed out')
        return {'status': 'updated'}
    monkeypatch.setattr(updater, 'update_host', update)
    assert updater.main() == 1
    rows = {row['agent_id']: row for row in json.loads(report.read_text())}
    assert rows['ok']['status'] == 'updated'
    assert rows['offline']['status'] == 'failed'
    assert rows['offline']['error'] == 'SSH timed out'


@pytest.mark.parametrize('actual_id,expected_id,allowed', [('node-1', 'node-1', True), ('node-2', 'node-1', False)])
def test_probe_reads_live_process_identity(tmp_path, monkeypatch, actual_id, expected_id, allowed):
    module = load('update-agent-remote')
    binary = tmp_path / 'binary'
    binary.write_bytes(b'agent')
    module.BINARY = binary
    process_dir = tmp_path / 'proc/123'
    process_dir.mkdir(parents=True)
    (process_dir / 'environ').write_bytes(b'OTHER=value\0FLEET_AGENT_ID=' + actual_id.encode() + b'\0')
    real_path = Path
    monkeypatch.setattr(module, 'Path', lambda *parts: real_path(tmp_path, *[str(part).lstrip('/') for part in parts]))
    monkeypatch.setattr(module.os, 'geteuid', lambda: 0)
    def command(*args):
        if 'is-active' in args:
            return 'active'
        if '--property=ExecStart' in args:
            return '{ path=/opt/fleet-agent/fleet-agent ; argv[]=/opt/fleet-agent/fleet-agent ; }'
        return '123'
    monkeypatch.setattr(module, 'command', command)
    if allowed:
        assert module.verify_identity(expected_id) == '123'
    else:
        with pytest.raises(RuntimeError, match='identity does not match'):
            module.verify_identity(expected_id)


@pytest.mark.parametrize('reply,skip', [('[]', True), ('invalid-json', False)])
def test_installer_empty_or_invalid_inventory_never_updates_nodes(tmp_path, reply, skip):
    source = (ROOT / 'install.sh').read_text().rsplit('\nmain "$@"', 1)[0]
    functions = tmp_path / 'functions.sh'
    functions.write_text(source)
    (tmp_path / 'deploy/docker').mkdir(parents=True)
    result = subprocess.run(['sh', '-c', '''
. "$1"
APP_DIR="$2"
record_install_stage() { :; }
docker_compose() { printf '%s' "$reply"; }
reply="$3"
update_existing_agents
''', 'sh', str(functions), str(tmp_path), reply], capture_output=True, text=True, timeout=10)
    assert (result.returncode == 0) == skip
    assert 'No registered agents to update' in result.stdout if skip else 'Traceback' in result.stderr


def test_rollback_uses_running_image_when_disk_already_contains_broken_update(remote, monkeypatch):
    remote.BINARY.write_bytes(b'broken new disk image')
    def verify(checksum):
        if checksum != remote.sha256(b'old executable'):
            raise RuntimeError('new process crashed')
    monkeypatch.setattr(remote, 'verify_running', verify)
    with pytest.raises(RuntimeError, match='previous binary restored'):
        remote.update('node-1', b'broken new disk image', remote.sha256(b'broken new disk image'))
    assert remote.BINARY.read_bytes() == b'old executable'
    assert remote.BINARY.with_name('fleet-agent.previous').read_bytes() == b'old executable'
