from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.db import Base
from app.models import Host, HostPackage, HostUser
from app.services.installation_readiness import inspect_host


@pytest.fixture
def db():
    engine = create_engine('sqlite:///:memory:')
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        yield session
    engine.dispose()


@pytest.mark.parametrize('missing', ['registration', 'heartbeat', 'packages', 'users', None])
def test_requires_fresh_registration_and_both_inventories(db, missing):
    now = datetime.now(timezone.utc)
    since = now - timedelta(seconds=30)
    old = now - timedelta(hours=1)
    if missing != 'registration':
        host = Host(agent_id='node', hostname='node', ip_address='192.0.2.10',
                    last_seen=old if missing == 'heartbeat' else now)
        db.add(host)
        db.flush()
        db.add(HostPackage(host_id=host.id, name='bash', arch='amd64', version='1',
                           manager='apt', collected_at=old if missing == 'packages' else now))
        db.add(HostUser(host_id=host.id, username='root', uid=0,
                        last_seen=old if missing == 'users' else now))
        db.commit()
    result = inspect_host(db, 'node-alias', '192.0.2.10', since)
    assert result['ready'] == (missing is None)
    if missing is None:
        assert result['users'] == 1
        assert result['packages'] == 1
    else:
        assert 'waiting' in result


def test_does_not_guess_when_host_identity_is_ambiguous(db):
    now = datetime.now(timezone.utc)
    db.add_all([Host(agent_id='one', hostname='same', last_seen=now),
                Host(agent_id='two', hostname='same', last_seen=now)])
    db.commit()
    result = inspect_host(db, 'same', '', now - timedelta(seconds=10))
    assert result == {'target': 'same', 'ready': False, 'waiting': 'ambiguous host identity'}
