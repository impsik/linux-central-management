from types import SimpleNamespace

from app.routers import reports


class _Result:
    def __init__(self, rows):
        self._rows = rows

    def all(self):
        return list(self._rows)


class _DB:
    def __init__(self, rows):
        self._rows = rows

    def execute(self, _query):
        return _Result(self._rows)


def test_hosts_updates_report_filters_rows_by_owner_visibility(monkeypatch):
    rows = [
        SimpleNamespace(
            agent_id='a1', hostname='owned', fqdn=None, ip_address=None,
            os_id='ubuntu', os_version='24.04', kernel='k1',
            labels={'owner': 'imre'}, last_seen=None, reboot_required=False,
            updates=1, security_updates=1,
        ),
        SimpleNamespace(
            agent_id='a2', hostname='foreign', fqdn=None, ip_address=None,
            os_id='ubuntu', os_version='24.04', kernel='k2',
            labels={'owner': 'alice'}, last_seen=None, reboot_required=False,
            updates=2, security_updates=0,
        ),
    ]

    monkeypatch.setattr(
        reports,
        'is_host_visible_to_user',
        lambda db, user, host: str((host.labels or {}).get('owner', '')).strip() == 'imre',
    )

    out = reports.hosts_updates_report(
        only_pending=False,
        online_only=False,
        sort='hostname',
        order='asc',
        limit=500,
        offset=0,
        db=_DB(rows),
        user=SimpleNamespace(username='imre', role='operator'),
    )

    assert out['total'] == 1
    assert len(out['items']) == 1
    assert out['items'][0]['agent_id'] == 'a1'
