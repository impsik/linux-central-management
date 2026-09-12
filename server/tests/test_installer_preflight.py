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
def test_standard_install_questions_and_secret_preservation(installer, tmp_path, existing):
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
    trace = tmp_path / 'prompts'
    harness = r'''
. "$1"
INSTALL_DIR="$2"
trace="$3"
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
sync_postgres_password() { :; }
wait_for_health() { return 0; }
write_inventory() { [ -z "$1" ] || exit 88; }
main
'''
    result = subprocess.run(['sh', '-c', harness, 'sh', str(installer), str(app), str(trace)],
                            cwd=tmp_path, capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
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
