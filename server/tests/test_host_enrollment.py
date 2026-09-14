from datetime import datetime, timedelta, timezone
import re

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import pytest
from sqlalchemy import select

from test_onboarding_api import setup_api


@pytest.fixture
def enroll_api(setup_api, monkeypatch, tmp_path):
    from app.routers import enrollment
    from app.config import settings
    client, db = setup_api
    client.app.include_router(enrollment.router)
    client.base_url = 'https://fleet.example.test'
    monkeypatch.setattr(enrollment, 'bootstrap_source', lambda url: b'# verified bootstrap\n')
    monkeypatch.setattr(settings, 'agent_terminal_token', 'server-wide-secret')
    monkeypatch.setenv('FLEET_ENROLLMENT_CERT_DIR', str(tmp_path))
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'test-ca')])
    now = datetime.now(timezone.utc)
    ca = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
          .public_key(ca_key.public_key()).serial_number(1)
          .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=500))
          .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
          .sign(ca_key, hashes.SHA256()))
    (tmp_path / 'terminal-ca.crt').write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    (tmp_path / 'terminal-ca.key').write_bytes(ca_key.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr = x509.CertificateSigningRequestBuilder().subject_name(name).sign(key, hashes.SHA256())
    payload = {'hostname': 'joined-node', 'os_id': 'ubuntu', 'os_version': '24.04',
               'csr': csr.public_bytes(serialization.Encoding.PEM).decode()}
    return client, db, payload


def issue(client):
    client.cookies.set('fleet_session', 'admin')
    response = client.post('/onboarding/enrollments')
    assert response.status_code == 200, response.text
    data = response.json()
    token = re.search(r'printf %s ([\w-]+) \| sudo', data['command']).group(1)
    return data, token


def redeem(client, token, payload):
    return client.post('/agent/enroll/redeem', headers={
        'X-Fleet-Enrollment-Token': token, 'X-Real-IP': '192.0.2.20'}, json=payload)


def test_only_admin_can_issue_and_revoke(enroll_api):
    client, _, _ = enroll_api
    assert client.post('/onboarding/enrollments').status_code == 401
    for role in ['operator', 'readonly']:
        client.cookies.set('fleet_session', role)
        assert client.post('/onboarding/enrollments').status_code == 403
    data, _ = issue(client)
    client.cookies.set('fleet_session', 'operator')
    assert client.delete('/onboarding/enrollments/' + data['id']).status_code == 403


def test_redeem_once_with_individual_credentials_and_certificate(enroll_api):
    from app.models import Host, HostEnrollment, Job
    from app.services.enrollment import terminal_token_for_host
    client, db, payload = enroll_api
    data, token = issue(client)
    row = db.scalar(select(HostEnrollment))
    assert row.token_hash != token
    response = redeem(client, token, payload)
    assert response.status_code == 200, response.text
    body = response.json()
    assert response.headers['cache-control'] == 'no-store'
    assert body['agent_token'] != token
    assert body['terminal_token'] != 'server-wide-secret'
    host = db.scalar(select(Host))
    assert host.agent_id == data['agent_id']
    assert terminal_token_for_host(db, host) == body['terminal_token']
    assert host.agent_token_hash != body['agent_token']
    cert = x509.load_pem_x509_certificate(body['terminal_certificate'].encode())
    assert not cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    assert str(cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value[0].value) == '192.0.2.20'
    assert db.scalar(select(Job.job_type)) == 'query-users'
    assert redeem(client, token, payload).status_code == 401


@pytest.mark.parametrize('method', ['expired', 'revoked', 'invalid'])
def test_unusable_token_cannot_create_host(enroll_api, method):
    from app.models import Host, HostEnrollment
    client, db, payload = enroll_api
    data, token = issue(client)
    if method == 'expired':
        row = db.scalar(select(HostEnrollment))
        row.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        db.commit()
    elif method == 'revoked':
        assert client.delete('/onboarding/enrollments/' + data['id']).status_code == 200
    else:
        token = 'invalid-' + token
    assert redeem(client, token, payload).status_code == 401
    assert db.scalar(select(Host)) is None


def test_invalid_csr_does_not_burn_token(enroll_api):
    client, _, payload = enroll_api
    _, token = issue(client)
    assert redeem(client, token, dict(payload, csr='invalid')).status_code == 400
    assert redeem(client, token, payload).status_code == 200


def test_certificate_ignores_client_supplied_forwarded_prefix(enroll_api):
    client, _, payload = enroll_api
    _, token = issue(client)
    response = client.post('/agent/enroll/redeem', headers={
        'X-Fleet-Enrollment-Token': token, 'X-Real-IP': '192.0.2.20',
        'X-Forwarded-For': '198.51.100.77, 192.0.2.20'}, json=payload)
    assert response.status_code == 200, response.text
    cert = x509.load_pem_x509_certificate(response.json()['terminal_certificate'].encode())
    assert str(cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value[0].value) == '192.0.2.20'


def test_bootstrap_verified_before_execution_and_token_not_in_url(enroll_api):
    import hashlib
    client, _, _ = enroll_api
    data, token = issue(client)
    command = data['command']
    assert hashlib.sha256(b'# verified bootstrap\n').hexdigest() in command
    assert command.index('sha256sum --check') < command.index('sudo python3')
    assert token not in command.split(' -o ')[0]
    assert '/agent/enroll/bootstrap.py' in command


def test_tampered_bootstrap_is_never_executed(enroll_api, tmp_path):
    import os
    import subprocess
    client, _, _ = enroll_api
    data, _ = issue(client)
    curl = tmp_path / 'curl'
    curl.write_text('#!/bin/sh\nwhile [ "$1" != "-o" ]; do shift; done\nprintf "malicious code" > "$2"\n')
    curl.chmod(0o755)
    sudo = tmp_path / 'sudo'
    sudo.write_text('#!/bin/sh\necho EXECUTED > "$MARKER"\n')
    sudo.chmod(0o755)
    marker = tmp_path / 'executed'
    env = dict(os.environ, PATH=str(tmp_path) + ':' + os.environ['PATH'], MARKER=str(marker))
    result = subprocess.run(['sh', '-c', data['command']], env=env, capture_output=True, timeout=10)
    assert result.returncode != 0
    assert not marker.exists()
