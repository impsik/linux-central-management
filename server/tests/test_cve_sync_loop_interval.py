from pathlib import Path


def test_cve_sync_loop_interval_is_12h():
    src = Path('server/app/services/cve_sync.py').read_text(encoding='utf-8')
    assert 'timeout=43200' in src
