# CONFIG is prepended by the authenticated Master's enrollment command generator.
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import platform
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request


def run(*args):
    subprocess.run(args, check=True)


def save(path, content, mode=0o600):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as temp:
        os.fchmod(temp.fileno(), mode)
        temp.write(content.encode() if isinstance(content, str) else content)
    os.replace(temp.name, path)


def main():
    if os.geteuid() != 0:
        sys.exit('Run the generated command with sudo.')
    os.umask(0o077)
    if not Path('/run/systemd/system').is_dir():
        sys.exit('A running systemd Linux host is required.')
    arch = {'x86_64': 'amd64', 'aarch64': 'arm64'}.get(platform.machine())
    if not arch:
        sys.exit('Supported architectures: x86_64 and aarch64.')
    state_path = Path('/var/lib/fleet-agent/enrollment.json')
    if Path('/etc/fleet-agent.env').exists() and not state_path.exists():
        sys.exit('An agent is already configured. Enrollment is for new hosts and does not overwrite existing credentials.')
    token = sys.stdin.read(256).strip()
    if not token:
        sys.exit('Missing one-time enrollment token.')
    release = {}
    for line in Path('/etc/os-release').read_text().splitlines():
        if '=' in line:
            key, value = line.split('=', 1)
            release[key] = value.strip('"')
    master_hostname = urllib.parse.urlsplit(CONFIG['url']).hostname
    master_ip = CONFIG.get('master_ip')
    if master_ip:
        master_ip = str(ipaddress.IPv4Address(master_ip))
        try:
            resolved = socket.gethostbyname(master_hostname)
        except OSError:
            resolved = ''
        if resolved != master_ip:
            # The signed bootstrap explicitly supplies this Master address.
            hosts = Path('/etc/hosts')
            lines = [line for line in hosts.read_text().splitlines()
                     if not line.endswith('# fleet-enrollment-master')]
            with hosts.open('w') as output:
                output.write('\n'.join(lines) + f'\n{master_ip} {master_hostname} # fleet-enrollment-master\n')
    print('Checking prerequisites...', flush=True)
    if not shutil.which('openssl'):
        if shutil.which('apt-get'):
            run('apt-get', 'update')
            run('apt-get', 'install', '-y', 'openssl', 'ca-certificates')
        elif shutil.which('dnf'):
            run('dnf', 'install', '-y', 'openssl', 'ca-certificates')
        elif shutil.which('yum'):
            run('yum', 'install', '-y', 'openssl', 'ca-certificates')
        else:
            sys.exit('Install openssl and ca-certificates, then retry.')
    context = ssl.create_default_context(cadata=CONFIG['ca'])

    def request(path, payload=None):
        headers = {'Content-Type': 'application/json'}
        if payload is not None:
            headers['X-Fleet-Enrollment-Token'] = token
        req = urllib.request.Request(CONFIG['url'] + path, headers=headers,
                                     data=json.dumps(payload).encode() if payload is not None else None)
        # Prevent redirecting enrollment credentials to another origin.
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *args, **kwargs):
                return None
        opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=context), NoRedirect())
        with opener.open(req, timeout=60) as response:
            return response.read()

    request('/health')
    print('Downloading and verifying the agent...', flush=True)
    binary = request('/agent/enroll/binary/' + arch)
    if hashlib.sha256(binary).hexdigest() != CONFIG['hashes'][arch]:
        sys.exit('Agent checksum mismatch. Generate a new command if the Master was updated.')
    if state_path.exists():
        state = json.loads(state_path.read_text())
        if state['url'] != CONFIG['url']:
            sys.exit('An unfinished enrollment belongs to a different Master.')
        credentials = state['credentials']
    else:
        print('Registering with the Master...', flush=True)
        with tempfile.TemporaryDirectory() as temp:
            key = temp + '/key.pem'
            csr = temp + '/request.pem'
            run('openssl', 'req', '-new', '-newkey', 'rsa:2048', '-nodes', '-keyout', key,
                '-out', csr, '-subj', '/CN=fleet-node')
            credentials = json.loads(request('/agent/enroll/redeem', {
                'hostname': socket.gethostname(), 'os_id': release.get('ID', ''),
                'os_version': release.get('VERSION_ID', ''), 'csr': Path(csr).read_text(),
            }))
            save('/etc/fleet-agent/terminal.key', Path(key).read_bytes())
            save(state_path, json.dumps({'url': CONFIG['url'], 'credentials': credentials}))
    save('/opt/fleet-agent/fleet-agent', binary, 0o755)
    save('/etc/fleet-agent/master-ca.crt', CONFIG['ca'], 0o644)
    save('/var/lib/fleet-agent/agent-token', credentials['agent_token'])
    env = {
        'FLEET_SERVER_URL': CONFIG['url'], 'FLEET_AGENT_ID': credentials['agent_id'],
        'FLEET_AGENT_TOKEN_FILE': '/var/lib/fleet-agent/agent-token',
        'SSL_CERT_FILE': '/etc/fleet-agent/master-ca.crt',
        'FLEET_TERMINAL_BACKEND': 'login',
    }
    if credentials['terminal_token']:
        save('/etc/fleet-agent/terminal.crt', credentials['terminal_certificate'], 0o644)
        env.update(FLEET_TERMINAL_TOKEN=credentials['terminal_token'], FLEET_TERMINAL_LISTEN='auto:18080',
                   FLEET_TERMINAL_TLS_CERT='/etc/fleet-agent/terminal.crt',
                   FLEET_TERMINAL_TLS_KEY='/etc/fleet-agent/terminal.key')
        master = urllib.parse.urlsplit(CONFIG['url']).hostname
        master_ip = str(ipaddress.IPv4Address(socket.gethostbyname(master)))
        if shutil.which('ufw') and 'Status: active' in subprocess.check_output(['ufw', 'status'], text=True):
            run('ufw', 'allow', 'from', master_ip, 'to', 'any', 'port', '18080', 'proto', 'tcp')
        elif shutil.which('firewall-cmd') and subprocess.run(['firewall-cmd', '--state'], capture_output=True).returncode == 0:
            rule = f'rule family="ipv4" source address="{master_ip}" port port="18080" protocol="tcp" accept'
            run('firewall-cmd', '--permanent', '--add-rich-rule=' + rule)
            run('firewall-cmd', '--add-rich-rule=' + rule)
    save('/etc/fleet-agent.env', ''.join(f'{key}={value}\n' for key, value in env.items()))
    save('/etc/systemd/system/fleet-agent.service', '''[Unit]
Description=Fleet Agent
After=network-online.target
Wants=network-online.target
[Service]
EnvironmentFile=/etc/fleet-agent.env
ExecStart=/opt/fleet-agent/fleet-agent
Restart=always
RestartSec=2
[Install]
WantedBy=multi-user.target
''', 0o644)
    run('systemctl', 'daemon-reload')
    run('systemctl', 'enable', '--now', 'fleet-agent')
    run('systemctl', 'restart', 'fleet-agent')
    run('systemctl', 'is-active', '--quiet', 'fleet-agent')
    state_path.unlink()
    print('Agent started. Return to Connect a Linux host to follow inventory progress.')
    if not credentials['terminal_token']:
        print('Console is disabled on the Master; inventory and management are available.')


if __name__ == '__main__':
    try:
        main()
    except urllib.error.HTTPError as exc:
        sys.exit(f'Master rejected enrollment (HTTP {exc.code}). Check token expiry or generate a new command.')
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        sys.exit(f'Enrollment stopped: {exc}. Correct the problem and retry the command.')
