from pathlib import Path


def test_phase3_host_filters_scripts_are_split_and_loaded():
    root = Path(__file__).resolve().parents[2]
    templates = root / "server" / "app" / "templates"

    index_html = (templates / "index.html").read_text(encoding="utf-8")
    assert '/assets/fleet-phase3-host-filters-ui.js' in index_html
    assert '/assets/fleet-phase3-host-filters-vuln.js' in index_html
    assert '/assets/fleet-phase3-host-filters.js' in index_html

    orchestrator = (templates / "fleet-phase3-host-filters.js").read_text(encoding="utf-8")
    assert 'phase3HostFiltersUi.initHostFiltersUi' in orchestrator
    assert 'phase3HostFiltersVuln.initHostFiltersVuln' in orchestrator


def test_phase3_vuln_upgrade_status_copy_smoke():
    root = Path(__file__).resolve().parents[2]
    vuln_js = (root / "server" / "app" / "templates" / "fleet-phase3-host-filters-vuln.js").read_text(encoding="utf-8")

    # CVE flow status lines used by UI and support docs/operators.
    assert 'Running CVE check…' in vuln_js
    assert 'CVE check started (job_id: ' in vuln_js
    assert 'Enter a CVE or a package name.' in vuln_js

    # Upgrade status rendering strings (package mode + CVE mode)
    assert 'Starting CVE upgrade on ' in vuln_js
    assert 'Starting upgrade of ' in vuln_js
    assert 'Selected: ' in vuln_js
    assert 'Run CVE check to see affected packages.' in vuln_js
