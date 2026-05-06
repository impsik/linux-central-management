from pathlib import Path


def test_cve_sync_loop_interval_is_12h():
    src = Path('server/app/services/cve_sync.py').read_text(encoding='utf-8')
    assert 'timeout=43200' in src


def test_ubuntu_textual_severity_mapping_is_present():
    src = Path('server/app/services/cve_sync.py').read_text(encoding='utf-8')
    assert '"low": 3.9' in src
    assert '"medium": 6.9' in src
    assert '"high": 8.9' in src
    assert '"critical": 10.0' in src
    assert 'parse_ubuntu_severity(text)' in src
