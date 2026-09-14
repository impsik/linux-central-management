"""Admin-issued one-time enrollment; redemption never uses a shared agent secret."""
from datetime import datetime, timedelta, timezone
import hashlib
import ipaddress
import os
from urllib.parse import urlsplit
import secrets
import shlex
import uuid

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, Response
from pydantic import BaseModel, Field
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from ..db import get_db
from ..deps import require_admin_user
from ..models import Host, HostEnrollment
from ..services.agent_auth import hash_agent_token
from ..services.audit import log_event
from ..services.enrollment import artifact_path, bootstrap_source, enrollment_path, node_terminal_token
from ..services.jobs import create_job_with_runs

router = APIRouter(tags=['enrollment'])


def base_url(request):
    url = str(request.base_url).rstrip('/')
    if not url.startswith('https://'):
        raise HTTPException(400, 'Host enrollment requires the public HTTPS URL')
    return url


@router.get('/agent/enroll/bootstrap.py')
def bootstrap(request: Request):
    try:
        body = bootstrap_source(base_url(request))
    except OSError:
        raise HTTPException(503, 'Enrollment files unavailable; update the Master with install.sh')
    return Response(body, media_type='text/plain', headers={'Cache-Control': 'no-store'})


@router.get('/agent/enroll/binary/{arch}')
def binary(arch: str):
    try:
        path = artifact_path(arch)
    except ValueError:
        raise HTTPException(404)
    if not path.is_file():
        raise HTTPException(503, 'Agent binary unavailable')
    return FileResponse(path, media_type='application/octet-stream')


@router.post('/onboarding/enrollments')
def issue(request: Request, db: Session = Depends(get_db), user=Depends(require_admin_user)):
    url = base_url(request)
    try:
        script = bootstrap_source(url)
    except OSError:
        raise HTTPException(503, 'Enrollment files unavailable; update the Master with install.sh')
    token = secrets.token_urlsafe(32)
    row = HostEnrollment(token_hash=hash_agent_token(token), agent_id='node-' + secrets.token_hex(12),
                         created_by=user.username, expires_at=datetime.now(timezone.utc) + timedelta(minutes=15))
    db.add(row)
    db.flush()
    log_event(db, action='host.enrollment.created', actor=user, request=request,
              target_type='enrollment', target_id=str(row.id), meta={'agent_id': row.agent_id})
    db.commit()
    digest = hashlib.sha256(script).hexdigest()
    # The only untrusted-TLS download is public bootstrap code. Its digest from
    # this authenticated UI is checked BEFORE sudo/execution or token transmission.
    address = os.environ.get('FLEET_ENROLLMENT_MASTER_IP', '')
    resolve = ''
    if address:
        parsed = urlsplit(url)
        address = str(ipaddress.IPv4Address(address))
        resolve = '--resolve ' + shlex.quote(f'{parsed.hostname}:{parsed.port or 443}:{address}') + ' '
    command = (
        '(umask 077; t=$(mktemp) || exit; trap \'rm -f "$t"\' EXIT; '
        f'curl --proto "=https" --insecure --fail --silent --show-error {resolve}{shlex.quote(url + "/agent/enroll/bootstrap.py")} -o "$t" && '
        f'printf \'%s  %s\\n\' {shlex.quote(digest)} "$t" | sha256sum --check --status && '
        f'printf %s {shlex.quote(token)} | sudo python3 "$t")'
    )
    return JSONResponse({'id': str(row.id), 'agent_id': row.agent_id,
                         'expires_at': row.expires_at.isoformat(), 'command': command},
                        headers={'Cache-Control': 'no-store'})


@router.delete('/onboarding/enrollments/{enrollment_id}')
def revoke(enrollment_id: uuid.UUID, db: Session = Depends(get_db), user=Depends(require_admin_user)):
    db.execute(update(HostEnrollment).where(HostEnrollment.id == enrollment_id,
               HostEnrollment.used_at.is_(None)).values(expires_at=datetime.now(timezone.utc)))
    db.commit()
    return {'ok': True}


class Redeem(BaseModel):
    hostname: str = Field(min_length=1, max_length=253, pattern=r'^[a-zA-Z0-9][a-zA-Z0-9._-]*$')
    os_id: str = Field(max_length=64)
    os_version: str = Field(max_length=64)
    csr: str = Field(max_length=8192)


@router.post('/agent/enroll/redeem')
def redeem(payload: Redeem, request: Request, db: Session = Depends(get_db)):
    token = request.headers.get('X-Fleet-Enrollment-Token', '')
    if not 20 <= len(token) <= 128:
        raise HTTPException(401, 'Invalid or expired enrollment token')
    now = datetime.now(timezone.utc)
    # Atomic compare-and-set is also the replay/concurrent-redemption guard.
    row = db.execute(update(HostEnrollment).where(
        HostEnrollment.token_hash == hash_agent_token(token),
        HostEnrollment.used_at.is_(None), HostEnrollment.expires_at > now,
    ).values(used_at=now).returning(HostEnrollment).execution_options(synchronize_session=False)).scalar_one_or_none()
    if row is None:
        db.rollback()
        raise HTTPException(401, 'Invalid or expired enrollment token')
    try:
        # The supported reverse proxies overwrite X-Real-IP with the peer
        # address. X-Forwarded-For can contain a client-supplied prefix and
        # must never determine a certificate's identity.
        peer = request.headers.get('X-Real-IP') or (request.client.host if request.client else '')
        address = str(ipaddress.ip_address(peer.strip()))
        csr = x509.load_pem_x509_csr(payload.csr.encode())
        if not csr.is_signature_valid:
            raise ValueError('invalid CSR signature')
        from cryptography.hazmat.primitives.asymmetric import rsa
        key = csr.public_key()
        if not isinstance(key, rsa.RSAPublicKey) or not 2048 <= key.key_size <= 4096:
            raise ValueError('Use a 2048–4096 bit RSA key')
        terminal_token = node_terminal_token(row.agent_id)
        cert_pem = ''
        if terminal_token:
            ca = x509.load_pem_x509_certificate(enrollment_path('terminal-ca.crt').read_bytes())
            ca_key = serialization.load_pem_private_key(enrollment_path('terminal-ca.key').read_bytes(), password=None)
            cert = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, row.agent_id)]))
                    .issuer_name(ca.subject).public_key(key).serial_number(x509.random_serial_number())
                    .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=397))
                    .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address(address))]), critical=False)
                    .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                    .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
                    .sign(ca_key, hashes.SHA256()))
            cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
        agent_token = secrets.token_urlsafe(32)
        if db.scalar(select(Host.id).where(Host.agent_id == row.agent_id)):
            raise ValueError('host identity already exists')
        db.add(Host(agent_id=row.agent_id, hostname=payload.hostname, ip_address=address,
                    os_id=payload.os_id, os_version=payload.os_version, last_seen=now,
                    agent_token_hash=hash_agent_token(agent_token)))
        create_job_with_runs(db=db, job_type='query-users', payload={'source': 'enrollment'},
                             agent_ids=[row.agent_id], created_by='system', commit=False)
        log_event(db, action='host.enrollment.redeemed', actor=None, request=request,
                  target_type='host', target_id=row.agent_id, meta={'hostname': payload.hostname})
        db.commit()
    except (ValueError, OSError, TypeError) as exc:
        db.rollback()
        raise HTTPException(400, 'Enrollment could not be completed; check the CSR and Master enrollment configuration') from exc
    return JSONResponse({'agent_id': row.agent_id, 'agent_token': agent_token,
                         'terminal_token': terminal_token, 'terminal_certificate': cert_pem,
                         'terminal_address': address}, headers={'Cache-Control': 'no-store'})
