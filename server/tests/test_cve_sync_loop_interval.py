from pathlib import Path


def test_cve_sync_loop_interval_is_12h():
    src = Path('server/app/services/cve_sync.py').read_text(encoding='utf-8')
    config = Path('server/app/config.py').read_text(encoding='utf-8')
    compose = Path('deploy/docker/docker-compose.yml').read_text(encoding='utf-8')

    assert 'cve_sync_interval_seconds: int = 43200' in config
    assert 'CVE_SYNC_INTERVAL_SECONDS' in compose
    assert 'settings.cve_sync_interval_seconds' in src


def test_ubuntu_textual_severity_mapping_is_present():
    src = Path('server/app/services/cve_sync.py').read_text(encoding='utf-8')
    assert '"low": 3.9' in src
    assert '"medium": 6.9' in src
    assert '"high": 8.9' in src
    assert '"critical": 10.0' in src
    assert 'parse_ubuntu_severity(text)' in src


def test_cve_sync_uses_bounded_http_timeout():
    src = Path('server/app/services/cve_sync.py').read_text(encoding='utf-8')
    assert 'CVE_SYNC_HTTP_TIMEOUT_SECONDS = 30' in src
    assert 'aiohttp.ClientTimeout(total=CVE_SYNC_HTTP_TIMEOUT_SECONDS)' in src
    assert 'aiohttp.ClientSession(timeout=timeout)' in src


def test_cve_sync_processes_releases_incrementally():
    src = Path('server/app/services/cve_sync.py').read_text(encoding='utf-8')
    assert 'release_cve_map = {}' in src
    assert 'await _upsert_cve_definitions(db, release_cve_map)' in src
    assert 'await _replace_release_lookup(db, codename, release_cve_map)' in src
    assert 'release_cve_map.clear()' in src
    assert 'gc.collect()' in src


def test_cve_sync_can_be_disabled_or_deferred():
    app_factory = Path('server/app/app_factory.py').read_text(encoding='utf-8')
    config = Path('server/app/config.py').read_text(encoding='utf-8')
    env = Path('deploy/docker/env.example').read_text(encoding='utf-8')
    src = Path('server/app/services/cve_sync.py').read_text(encoding='utf-8')

    assert 'cve_sync_enabled: bool = True' in config
    assert 'cve_sync_initial_delay_seconds: int = 0' in config
    assert 'if settings.cve_sync_enabled:' in app_factory
    assert 'CVE sync loop disabled by configuration' in app_factory
    assert 'settings.cve_sync_initial_delay_seconds' in src
    assert 'CVE_SYNC_ENABLED=true' in env
    assert 'CVE_SYNC_INITIAL_DELAY_SECONDS=0' in env
