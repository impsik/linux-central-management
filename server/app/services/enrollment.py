"""Enrollment artifacts and per-node Console credentials."""
import hashlib
import hmac
import os
from pathlib import Path

from sqlalchemy import select
from ..config import settings
from ..models import HostEnrollment


def enrollment_path(name):
    return Path(os.environ.get('FLEET_ENROLLMENT_CERT_DIR', '/run/fleet-enrollment')) / name


def artifact_path(arch):
    if arch not in ('amd64', 'arm64'):
        raise ValueError('unsupported architecture')
    return Path(os.environ.get('FLEET_ENROLLMENT_AGENT_DIR', '/app/enrollment-agents')) / f'fleet-agent-{arch}'


def node_terminal_token(agent_id):
    secret = settings.agent_terminal_token or ''
    if not secret:
        return ''
    return hmac.new(secret.encode(), ('enrollment-console:' + agent_id).encode(), hashlib.sha256).hexdigest()


def terminal_token_for_host(db, host):
    enrolled = db.scalar(select(HostEnrollment.id).where(
        HostEnrollment.agent_id == host.agent_id, HostEnrollment.used_at.is_not(None)))
    return node_terminal_token(host.agent_id) if enrolled else settings.agent_terminal_token


def bootstrap_source(base_url):
    ca = enrollment_path('master-ca.crt').read_text()
    hashes = {arch: hashlib.sha256(artifact_path(arch).read_bytes()).hexdigest()
              for arch in ('amd64', 'arm64')}
    config = {'url': base_url, 'ca': ca, 'hashes': hashes,
              'master_ip': os.environ.get('FLEET_ENROLLMENT_MASTER_IP', '')}
    template = Path(__file__).resolve().parents[1] / 'templates/join-node.py'
    return ('CONFIG = ' + repr(config) + '\n' + template.read_text()).encode()
