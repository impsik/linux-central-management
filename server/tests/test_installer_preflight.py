"""Exercise the real shell entry point with read-only probes and mutation stubs."""
from pathlib import Path
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def installer(tmp_path):
    source = (ROOT / 'install.sh').read_text().rsplit('\nmain "$@"', 1)[0]
    script = tmp_path / 'installer-functions.sh'
    script.write_text(source)
    return script


def run_installer(installer, tmp_path, *, family='apt', port='', dns='192.0.2.10',
                  git_ok=True, nginx=False, check=True, advanced=False, missing='', systemd='running'):
    trace = tmp_path / 'calls'
    harness = r'''
. "$1"
INSTALL_DIR="$2/app"
APP_DIR="$INSTALL_DIR"
REPO_URL=https://example.test/repo.git
FLEET_HOSTNAME=fleet.example.test
FLEET_SERVER_IP=192.0.2.10
INSTALL_NGINX="$3"
family="$4"
occupied="$5"
dns="$6"
git_ok="$7"
missing="$8"
systemd_state="$9"
trace="${10}"
mode="${11}"
advanced="${12}"
INSTALL_ADVANCED="$advanced"
have() { [ "$1" != "$missing" ] || return 1; case "$1" in apt-get) [ "$family" = apt ] ;; *) return 0 ;; esac; }
uname() { printf Linux; }
id() { printf 0; }
systemctl() { case "$1" in show) printf '%s' "$systemd_state";; *) return 1;; esac; }
ss() { [ -z "$occupied" ] || printf 'LISTEN 0 4096 0.0.0.0:%s 0.0.0.0:*\n' "$occupied"; }
timeout() { shift; "$@"; }
getent() { [ -z "$dns" ] || printf '%s STREAM fleet.example.test\n' "$dns"; }
git() { [ "$git_ok" = true ]; }
curl() { printf 401; }
sudo_cmd() { case "$1" in docker) return 0;; *) "$@";; esac; }
prompt() { printf 'prompt:%s\n' "$1" >> "$trace"; printf '%s' "$2"; }
install_packages() { printf mutation >> "$trace"; exit 0; }
ensure_repo() { printf mutation >> "$trace"; exit 0; }
if [ "$mode" = check ]; then main --check; else main; fi
'''
    result = subprocess.run(['sh', '-c', harness, 'sh', str(installer), str(tmp_path),
        'yes' if nginx else 'no', family, port, dns, str(git_ok).lower(), missing, systemd,
        str(trace), 'check' if check else 'install', str(advanced).lower()],
        cwd=tmp_path, capture_output=True, text=True, timeout=10)
    return result, trace.read_text() if trace.exists() else ''


def test_check_only_does_not_mutate_or_ask_for_secrets(installer, tmp_path):
    result, trace = run_installer(installer, tmp_path)
    assert result.returncode == 0, result.stderr
    assert 'Preflight passed' in result.stdout
    assert trace == ''
    assert not (tmp_path / 'app').exists()


@pytest.mark.parametrize(('kwargs', 'message'), [
    ({'port': '443', 'nginx': True}, 'Port 443'),
    ({'port': '80', 'nginx': True}, 'Port 80'),
    ({'port': '18000'}, 'Port 18000'),
    ({'dns': '192.0.2.99'}, 'not 192.0.2.10'),
    ({'git_ok': False}, 'Cannot reach repository'),
    ({'family': 'rpm', 'missing': 'go'}, 'Missing go'),
    ({'family': 'rpm', 'missing': 'nginx', 'nginx': True}, 'nginx is missing'),
    ({'systemd': 'offline'}, 'running systemd'),
])
def test_failed_preflight_blocks_installation(installer, tmp_path, kwargs, message):
    result, trace = run_installer(installer, tmp_path, check=False, **kwargs)
    assert result.returncode != 0
    assert message in result.stderr
    assert 'mutation' not in trace
    assert not (tmp_path / 'app').exists()


def test_external_proxy_may_own_https_port(installer, tmp_path):
    result, trace = run_installer(installer, tmp_path, port='443')
    assert result.returncode == 0, result.stderr
    assert 'mutation' not in trace


def test_missing_dns_explains_local_fallback(installer, tmp_path):
    result, _ = run_installer(installer, tmp_path, dns='')
    assert result.returncode == 0, result.stderr
    assert 'browser machine' in result.stderr


def test_preflight_runs_before_first_install_mutation(installer, tmp_path):
    result, trace = run_installer(installer, tmp_path, check=False)
    assert result.returncode == 0, result.stderr
    assert 'Preflight passed' in result.stdout
    assert trace == 'mutation'


def test_rpm_prepared_node_can_pass(installer, tmp_path):
    result, _ = run_installer(installer, tmp_path, family='rpm')
    assert result.returncode == 0, result.stderr


def test_standard_mode_does_not_prompt_for_rotation(installer, tmp_path):
    result = subprocess.run(['sh', '-c', '. "$1"; advanced=false; confirm() { echo unexpected; }; advanced_confirm rotate || :',
                              'sh', str(installer)], capture_output=True, text=True)
    assert result.stdout == ''


@pytest.mark.parametrize('existing', [False, True])
@pytest.mark.parametrize('attach', [False, True])
@pytest.mark.parametrize('agent_update_ok', [False, True])
def test_standard_install_questions_and_secret_preservation(installer, tmp_path, existing, attach, agent_update_ok):
    app = tmp_path / 'app'
    (app / 'deploy/docker').mkdir(parents=True)
    (app / 'env.example').write_text('SERVER_URL=\n')
    config = ('BOOTSTRAP_USERNAME=admin\nBOOTSTRAP_PASSWORD=change-me\n'
              'AGENT_SHARED_TOKEN=change-me\nMFA_ENCRYPTION_KEY=\nPOSTGRES_PASSWORD=change-me\nAGENT_TERMINAL_TOKEN=\n')
    (app / 'deploy/docker/env.example').write_text(config)
    if existing:
        (app / 'deploy/docker/.env').write_text(
            'BOOTSTRAP_USERNAME=existing-admin\nBOOTSTRAP_PASSWORD=existing-password\n'
            'AGENT_SHARED_TOKEN=existing-token\nMFA_ENCRYPTION_KEY=existing-key\n'
            'POSTGRES_PASSWORD=existing-postgres\nAGENT_TERMINAL_TOKEN=existing-terminal\n')
        (app / '.env').write_text('SERVER_URL=https://fleet.example.test\nFLEET_SERVER_IP=192.0.2.10\nINSTALL_NGINX=true\n')
    helper = app / 'add-host.sh'
    helper.write_text('#!/bin/sh\nprintf "%s|%s\\n" "$ATTACH_HOSTS" "$ANSIBLE_USER" > attached\n')
    helper.chmod(0o755)
    trace = tmp_path / 'prompts'
    harness = r'''
. "$1"
INSTALL_DIR="$2"
trace="$3"
ATTACH_HOSTS="$4"
agent_update_ok="$5"
ANSIBLE_USER=operator
unset FLEET_HOSTNAME INSTALL_NGINX
FLEET_SERVER_IP=192.0.2.10
primary_ip() { printf 192.0.2.10; }
prompt() { printf 'prompt:%s\n' "$1" >> "$trace"; printf '%s' "$2"; }
prompt_secret_or_generate() { printf 'secret:%s\n' "$1" >> "$trace"; printf new-password; }
random_password() { printf new-password; }
random_hex() { printf generated-token; }
fernet_key() { printf generated-key; }
preflight() { printf 'checked\n' >> "$trace"; }
install_packages() { printf 'installed\n' >> "$trace"; }
ensure_repo() { :; }
prepare_https() { :; }
sudo_cmd() { case "$1" in base64) printf certificate;; *) return 0;; esac; }
docker_compose() { :; }
installation_fingerprint() { printf test-fingerprint; }
sync_postgres_password() { :; }
wait_for_health() { return 0; }
write_inventory() { :; }
update_existing_agents() { [ "$agent_update_ok" = true ]; }
main
'''
    result = subprocess.run(['sh', '-c', harness, 'sh', str(installer), str(app), str(trace), 'first-node' if attach else '', str(agent_update_ok).lower()],
                            cwd=tmp_path, capture_output=True, text=True, timeout=10)
    assert result.returncode == (0 if agent_update_ok else 1), result.stderr
    if not agent_update_ok:
        assert 'Status: Master ready; agent updates pending' in result.stdout
        assert 'STAGE=agent-update-pending' in Path(str(app) + '.install-progress').read_text()
    prompts = trace.read_text()
    assert prompts.index('checked') < prompts.index('installed')
    assert 'Internal CA certificate path' not in prompts
    assert 'Fleet server IPv4 address' not in prompts
    assert 'Managed hosts' not in prompts
    assert 'Rotate' not in prompts
    env = (app / 'deploy/docker/.env').read_text()
    if existing:
        assert 'Admin username' not in prompts
        for secret in ('existing-password', 'existing-token', 'existing-key', 'existing-postgres', 'existing-terminal'):
            assert secret in env
    else:
        assert 'Admin username' in prompts
        assert 'secret:Bootstrap admin password' in prompts
        assert 'AGENT_TERMINAL_TOKEN=\n' in env
    assert 'INSTALL_NGINX=true' in (app / '.env').read_text()
    assert 'Connect your first Linux host' in result.stdout
    assert (app / 'attached').exists() == attach
    if attach:
        assert (app / 'attached').read_text() == 'first-node|operator\n'


@pytest.mark.parametrize('family', ['apt', 'rpm'])
def test_https_uses_distribution_specific_trust_and_nginx_paths(installer, tmp_path, family):
    trace = tmp_path / 'https-calls'
    harness = r'''
. "$1"
trace="$2"
family="$3"
have() { case "$1" in apt-get|update-ca-certificates) [ "$family" = apt ];; ss) return 1;; *) return 0;; esac; }
sudo_cmd() { printf '%s\n' "$*" >> "$trace"; return 0; }
getent() { printf '192.0.2.10 fleet.example.test\n'; }
prepare_https https://fleet.example.test 192.0.2.10 /test-ca/fleet-ca.crt true
'''
    result = subprocess.run(['sh', '-c', harness, 'sh', str(installer), str(trace), family],
                            cwd=tmp_path, capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
    commands = trace.read_text()
    if family == 'apt':
        assert 'update-ca-certificates' in commands
        assert '/etc/nginx/sites-available/fleet' in commands
    else:
        assert 'update-ca-trust extract' in commands
        assert '/etc/nginx/conf.d/fleet.conf' in commands
        assert 'sites-available' not in commands
    assert 'nginx -t' in commands


@pytest.mark.parametrize(('owner', 'allowed'), [('nginx', True), ('apache2', False), ('', False)])
def test_nginx_port_exception_checks_socket_owner(installer, owner, allowed):
    harness = r'''
. "$1"
owner="$2"
sudo_cmd() { printf 'LISTEN 0 4096 0.0.0.0:443 0.0.0.0:* users:(("%s",pid=1,fd=4))\n' "$owner"; }
port_owned_by_nginx 443
'''
    result = subprocess.run(['sh', '-c', harness, 'sh', str(installer), owner], capture_output=True, text=True)
    assert (result.returncode == 0) is allowed


@pytest.mark.parametrize('advanced', ['false', 'true'])
@pytest.mark.parametrize('nginx', ['true', 'false'])
def test_update_restart_preserves_endpoint_answers(installer, tmp_path, advanced, nginx):
    app = tmp_path / 'app'
    app.mkdir()
    child = app / 'install.sh'
    child.write_text('''#!/bin/sh
printf 'resumed:%s|%s|%s|%s|%s|%s\\n' "$FLEET_HOSTNAME" "$FLEET_SERVER_IP" "$FLEET_CA_CERT" "$INSTALL_NGINX" "$INSTALL_ADVANCED" "$FLEET_INSTALL_REEXEC"
''')
    child.chmod(0o755)
    harness = r'''
. "$1"
INSTALL_DIR="$2/app"
INSTALL_ADVANCED="$3"
nginx_answer="$4"
unset FLEET_HOSTNAME FLEET_SERVER_IP FLEET_CA_CERT INSTALL_NGINX FLEET_INSTALL_REEXEC
primary_ip() { printf 192.0.2.10; }
prompt() {
  case "$1" in
    Application*) printf chosen.example.test ;;
    'Fleet server IPv4'*) printf 192.0.2.20 ;;
    'Internal CA'*) printf '/etc/custom pki/ca.crt' ;;
    *) exit 91 ;;
  esac
}
confirm() { [ "$nginx_answer" = true ]; }
preflight() { :; }
install_packages() { :; }
ensure_repo() { update_existing_checkout; }
git() {
  case "$*" in
    *'rev-parse HEAD')
      if [ -f "$INSTALL_DIR/fetched" ]; then printf new; else printf old; fi ;;
    *'fetch origin --prune') touch "$INSTALL_DIR/fetched" ;;
  esac
}
main
'''
    result = subprocess.run(['sh', '-c', harness, 'sh', str(installer),
                             str(tmp_path), advanced, nginx],
                            cwd=tmp_path, capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
    ip = '192.0.2.20' if advanced == 'true' else '192.0.2.10'
    ca = '/etc/custom pki/ca.crt' if advanced == 'true' else '/etc/fleet-pki/fleet-ca.crt'
    assert f'resumed:chosen.example.test|{ip}|{ca}|{nginx}|{advanced}|1' in result.stdout


@pytest.mark.parametrize('resume,unchanged,healthy,skip', [
    ('true', True, True, True),
    ('true', False, True, False),
    ('true', True, False, False),
    ('false', True, True, False),
])
def test_resume_skips_only_unchanged_healthy_master(installer, tmp_path, resume, unchanged, healthy, skip):
    (tmp_path / 'deploy/docker').mkdir(parents=True)
    progress = tmp_path / 'progress'
    progress.write_text('STACK_FINGERPRINT=old\n')
    harness = r'''
. "$1"
APP_DIR="$2"
resume_file="$APP_DIR/progress"
resume="$3"
new_fingerprint="$4"
health="$5"
server_url=https://fleet.example.test
fleet_ca_cert=/etc/fleet-pki/ca.crt
postgres_password=secret
installation_fingerprint() { printf '%s' "$new_fingerprint"; }
wait_for_health() { [ "$health" = true ]; }
docker_compose() { printf 'DOCKER:%s\n' "$*"; }
sync_postgres_password() { :; }
start_server_stack
'''
    result = subprocess.run(['sh', '-c', harness, 'sh', str(installer), str(tmp_path),
                             resume, 'old' if unchanged else 'new', str(healthy).lower()],
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
    assert ('DOCKER:' not in result.stdout) == skip


def test_failed_server_start_does_not_mark_stage_complete(installer, tmp_path):
    (tmp_path / 'deploy/docker').mkdir(parents=True)
    result = subprocess.run(['sh', '-c', r'''
. "$1"
APP_DIR="$2"
resume_file="$APP_DIR/progress"
resume=false
installation_fingerprint() { printf new; }
docker_compose() { return 42; }
start_server_stack
''', 'sh', str(installer), str(tmp_path)], capture_output=True, text=True, timeout=10)
    assert result.returncode == 42
    saved = (tmp_path / 'progress').read_text()
    assert 'STAGE=server-start' in saved
    assert 'STACK_FINGERPRINT=' not in saved


def test_resume_restores_answers_without_prompts_or_check_writes(installer, tmp_path):
    app = tmp_path / 'app'
    progress = tmp_path / 'app.install-progress'
    original = ('STAGE=node-attach\nINSTALL_REF=cleanup\nFLEET_HOSTNAME=chosen.example.test\n'
                'FLEET_SERVER_IP=192.0.2.20\nFLEET_CA_CERT=/custom/ca.crt\n'
                'INSTALL_NGINX=false\nATTACH_HOSTS=node.example.test\nANSIBLE_USER=operator\n')
    progress.write_text(original)
    result = subprocess.run(['sh', '-c', r'''
. "$1"
INSTALL_DIR="$2"
primary_ip() { printf 192.0.2.10; }
prompt() { echo UNEXPECTED_PROMPT >&2; exit 91; }
preflight() {
  printf 'REF:%s\n' "$INSTALL_REF"
  printf 'RESTORED:%s|%s|%s|%s|%s|%s\n' "$application_host" "$fleet_server_ip" "$fleet_ca_cert" "$install_nginx" "$ATTACH_HOSTS" "$ANSIBLE_USER"
}
main --resume --check
''', 'sh', str(installer), str(app)], cwd=tmp_path, capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
    assert 'UNEXPECTED_PROMPT' not in result.stderr
    assert 'RESTORED:chosen.example.test|192.0.2.20|/custom/ca.crt|false|node.example.test|operator' in result.stdout
    assert 'REF:cleanup' in result.stdout
    assert progress.read_text() == original
    assert not app.exists()


@pytest.mark.parametrize('status', [0, 7])
def test_stage_logging_keeps_output_quiet_and_preserves_errors(installer, tmp_path, status):
    log = tmp_path / 'stage.log'
    log.write_text('earlier-stage-output\n')
    result = subprocess.run(['sh', '-c', r'''
. "$1"
FLEET_INSTALL_LOG="$2"
stage_command() { printf 'command detail\n'; printf 'stderr detail\n' >&2; return "$3"; }
run_logged 'Test stage' stage_command unused unused "$3"
printf 'CONTINUED\n'
''', 'sh', str(installer), str(log), str(status)], capture_output=True, text=True, timeout=10)
    assert result.returncode == status
    assert 'command detail' in log.read_text()
    assert 'stderr detail' in log.read_text()
    if status:
        assert 'command detail' in result.stderr
        assert 'stderr detail' in result.stderr
        assert 'earlier-stage-output' not in result.stderr
        assert 'CONTINUED' not in result.stdout
    else:
        assert 'command detail' not in result.stdout
        assert 'stderr detail' not in result.stderr
        assert 'Test stage: done' in result.stdout


def test_logging_does_not_mask_failure_inside_function(installer, tmp_path):
    log = tmp_path / 'stage.log'
    log.touch()
    result = subprocess.run(['sh', '-c', r'''
. "$1"
FLEET_INSTALL_LOG="$2"
fail_midway() { false; printf 'MUST_NOT_RUN\n'; }
run_logged 'Failing stage' fail_midway
''', 'sh', str(installer), str(log)], capture_output=True, text=True, timeout=10)
    assert result.returncode != 0
    assert 'MUST_NOT_RUN' not in log.read_text()


def test_install_log_is_private_and_reused_after_restart(installer, tmp_path):
    result = subprocess.run(['sh', '-c', r'''
. "$1"
APP_DIR="$2/app"
init_install_log
first_log="$FLEET_INSTALL_LOG"
printf 'before restart\n' >> "$FLEET_INSTALL_LOG"
init_install_log
[ "$first_log" = "$FLEET_INSTALL_LOG" ]
''', 'sh', str(installer), str(tmp_path)], capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
    logs = list((tmp_path / 'app.install-logs').glob('*.log'))
    assert len(logs) == 1
    assert logs[0].read_text() == 'before restart\n'
    assert logs[0].stat().st_mode & 0o077 == 0


@pytest.mark.parametrize('choice', ['1', '2', '3', 'unattended'])
def test_node_attachment_recovery(installer, tmp_path, choice):
    child = tmp_path / 'add-host.sh'
    child.write_text('''#!/bin/sh
set -eu
printf '%s|%s\\n' "$ATTACH_HOSTS" "$ANSIBLE_USER" >> attempts
if [ ! -f attempted ]; then touch attempted; exit 7; fi
''')
    child.chmod(0o755)
    result = subprocess.run(['sh', '-c', r'''
. "$1"
APP_DIR="$2"
resume_file="$APP_DIR/progress"
deploy_hosts=old-node
ansible_user=old-user
fleet_server_ip=192.0.2.10
fleet_ca_cert=/test/ca.crt
choice="$3"
is_tty() { [ "$choice" != unattended ]; }
prompt() {
  case "$1" in
    'Next action') printf '%s' "$choice" ;;
    'Managed host(s)'*) printf new-node ;;
    'SSH username') printf new-user ;;
  esac
}
attach_hosts_with_recovery
printf 'DEFERRED:%s\n' "$node_attach_deferred"
''', 'sh', str(installer), str(tmp_path), choice],
        cwd=tmp_path, capture_output=True, text=True, timeout=10)
    attempts = (tmp_path / 'attempts').read_text().splitlines()
    if choice == 'unattended':
        assert result.returncode == 7
        assert len(attempts) == 1
    elif choice == '3':
        assert result.returncode == 0
        assert len(attempts) == 1
        assert 'DEFERRED:true' in result.stdout
        assert 'STAGE=node-attach-deferred' in (tmp_path / 'progress').read_text()
    else:
        assert result.returncode == 0, result.stderr
        assert len(attempts) == 2
        assert attempts[1] == ('new-node|new-user' if choice == '2' else 'old-node|old-user')
        assert 'DEFERRED:false' in result.stdout
        if choice == '2':
            assert 'ATTACH_HOSTS=new-node' in (tmp_path / 'progress').read_text()


def test_normal_mode_deploys_selected_host_without_advanced_prompt(installer, tmp_path):
    result = subprocess.run(['sh', '-c', r'''
. "$1"
advanced=false
confirm() { echo UNEXPECTED_PROMPT; return 1; }
should_deploy_agents
''', 'sh', str(installer)], capture_output=True, text=True, timeout=10)
    assert result.returncode == 0
    assert 'UNEXPECTED_PROMPT' not in result.stdout


def test_inventory_preserves_existing_hosts_and_is_repeatable(installer, tmp_path):
    (tmp_path / 'ansible').mkdir()
    hosts = tmp_path / 'hosts'
    inventory = tmp_path / 'ansible/inventory.yml'
    hosts.write_text('existing ansible_user=original\n')
    inventory.write_text('all:\n  hosts:\n    existing:\n      ansible_user: original\n')
    result = subprocess.run(['sh', '-c', r'''
. "$1"
APP_DIR="$2"
write_inventory 'existing,new-node' operator
write_inventory 'existing,new-node' operator
''', 'sh', str(installer), str(tmp_path)], capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
    assert hosts.read_text() == 'existing ansible_user=original\nnew-node ansible_user=operator\n'
    assert inventory.read_text().count('    new-node:') == 1
    assert 'ansible_user: original' in inventory.read_text()


def test_https_setup_does_not_replace_install_exit_handler(installer, tmp_path):
    # Run certificate setup with system changes stubbed to exercise its cleanup trap.
    result = subprocess.run(['sh', '-c', r'''
. "$1"
trap 'printf "OUTER_EXIT\n"' EXIT
sudo_cmd() { :; }
prepare_https https://example.test 192.0.2.1 /tmp/unused-lcm-test-ca.crt false
false
''', 'sh', str(installer)], capture_output=True, text=True, timeout=10)
    assert result.returncode != 0
    assert 'OUTER_EXIT' in result.stdout
