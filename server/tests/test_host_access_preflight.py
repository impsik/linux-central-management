"""Run the host-access shell workflow with network/deployment commands stubbed."""
import json
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def helper(tmp_path):
    script = tmp_path / 'attach-functions.sh'
    script.write_text((ROOT / 'add-host.sh').read_text().rsplit('\nmain "$@"', 1)[0])
    return script


def run(helper, tmp_path, body):
    return subprocess.run(['sh', '-c', '. "$1"\n' + body,
                           str(ROOT / 'add-host.sh'), str(helper)],
                          cwd=tmp_path, text=True, capture_output=True, timeout=10)


def test_working_key_never_prompts(helper, tmp_path):
    result = run(helper, tmp_path, '''
ansible_user=imre
python3() { :; }
ssh() { printf '%s\\n' "$*"; }
confirm_access() { exit 91; }
prepare_host_access node.example.test
''')
    assert result.returncode == 0, result.stderr
    assert 'BatchMode=yes' in result.stdout
    assert 'StrictHostKeyChecking=yes' in result.stdout


@pytest.mark.parametrize('host', ['-oProxyCommand=oops', 'node:all', 'node;touch', 'node$(id)'])
def test_invalid_hosts_fail_before_network(helper, tmp_path, host):
    result = run(helper, tmp_path, f'''
ansible_user=imre
python3() {{ echo NETWORK_CALLED; }}
prepare_host_access '{host}'
''')
    assert result.returncode != 0
    assert 'NETWORK_CALLED' not in result.stdout


def test_missing_key_offers_copy_and_rechecks(helper, tmp_path):
    key = tmp_path / 'key'
    key.with_suffix('.pub').write_text('public-key')
    copy = tmp_path / 'ssh-copy-id'
    copy.write_text('#!/bin/sh\nprintf "COPY:%s\\n" "$*"\ntouch copied\n')
    copy.chmod(0o755)
    result = run(helper, tmp_path, f'''
ansible_user=imre
ssh_identity='{key}'
python3() {{ :; }}
is_tty() {{ return 1; }}
ssh_probe() {{ [ -f copied ]; }}
confirm_access() {{ printf '%s\\n' "$1"; }}
have() {{ return 0; }}
PATH="$PWD:$PATH"
prepare_host_access node.example.test
''')
    assert result.returncode == 0, result.stderr
    assert 'ssh-copy-id?' in result.stdout
    assert 'COPY:-i' in result.stdout
    assert 'StrictHostKeyChecking=yes' in result.stdout


def test_unreachable_node_never_copies_key(helper, tmp_path):
    result = run(helper, tmp_path, '''
ansible_user=imre
python3() { return 1; }
ssh() { echo COPIED; }
prepare_host_access node.example.test
''')
    assert result.returncode != 0
    assert 'COPIED' not in result.stdout


def test_sudo_password_is_separate_and_not_in_arguments(helper, tmp_path):
    result = run(helper, tmp_path, '''
umask 077
credentials_file="$PWD/credentials.json"
ansible_pass='ssh $secret with spaces'
become_pass=''
ansible_user=imre
target_pattern=node
HOSTS_FILE=hosts
is_tty() { return 0; }
prompt_secret() { printf 'different sudo password'; }
ansible() {
  printf '%s\\n' "$*"
  python3 -c 'import json,sys; sys.exit(not bool(json.load(open("credentials.json")).get("ansible_become_password")))'
}
check_host_sudo
''')
    assert result.returncode == 0, result.stderr
    values = json.loads((tmp_path / 'credentials.json').read_text())
    assert values == {'ansible_password': 'ssh $secret with spaces',
                      'ansible_become_password': 'different sudo password'}
    assert 'different sudo password' not in result.stdout
    assert 'ssh $secret' not in result.stdout
    assert (tmp_path / 'credentials.json').stat().st_mode & 0o077 == 0


def test_failed_sudo_stops_before_deployment(helper, tmp_path):
    result = run(helper, tmp_path, '''
credentials_file="$PWD/credentials.json"
run_ansible() { return 1; }
is_tty() { return 0; }
prompt_secret() { printf wrong; }
check_host_sudo
echo DEPLOY
''')
    assert result.returncode != 0
    assert 'DEPLOY' not in result.stdout


@pytest.mark.parametrize('reachable', [True, False])
def test_reverse_connection_is_checked_before_agent_install(helper, tmp_path, reachable):
    result = run(helper, tmp_path, f'''
tmp_dir="$PWD"
target_pattern=node
ROOT_DIR='{ROOT}'
go() {{ :; }}
verify_host_inventory() {{ printf 'INVENTORY_CHECK\\n' >> calls; }}
run_ansible() {{
  printf '%s\\n' "$*" >> calls
  case "$*" in *' -m uri '*|'-m uri '*) {'return 0' if reachable else 'return 1'} ;; esac
}}
deploy_agent http://master.example.test token '' '' '' '' node
''')
    calls = (tmp_path / 'calls').read_text()
    assert 'url=http://master.example.test/health' in calls
    assert 'validate_certs=true' in calls
    if reachable:
        assert result.returncode == 0, result.stderr
        assert calls.index('-m uri') < calls.index('dest=/opt/fleet-agent/fleet-agent')
        assert 'systemctl is-active fleet-agent' in calls
    else:
        assert result.returncode != 0
        assert '/opt/fleet-agent' not in calls
        assert 'systemctl' not in calls


def test_selected_user_overrides_saved_inventory_user(helper, tmp_path):
    result = run(helper, tmp_path, '''
ansible_user=corrected-user
target_pattern=node
HOSTS_FILE=hosts
credentials_file=credentials.json
ansible() { printf '%s\\n' "$@"; }
run_ansible -m command -a 'id -u'
''')
    assert result.returncode == 0, result.stderr
    assert '--extra-vars\nansible_user=corrected-user\n' in result.stdout


def test_readiness_uses_sudo_when_compose_exists_without_socket_access(helper, tmp_path):
    result = run(helper, tmp_path, '''
ROOT_DIR="$PWD"
mkdir -p deploy/docker
target_hosts=node
deployment_started=123
getent() { printf '192.0.2.10 STREAM node\n'; }
docker() { [ "$1" != ps ]; }
as_root() { printf 'ROOT:%s\n' "$*" >> calls; }
verify_host_inventory
''')
    assert result.returncode == 0, result.stderr
    calls = (tmp_path / 'deploy/docker/calls').read_text()
    assert 'ROOT:docker compose exec -T server python -m app.services.installation_readiness' in calls
