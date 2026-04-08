def test_phase3_host_filters_scripts_are_split_and_loaded(templates_dir):
    index_html = (templates_dir / "index.html").read_text(encoding="utf-8")
    assert '/assets/fleet-phase3-host-filters-ui.js' in index_html
    assert '/assets/fleet-phase3-host-filters-vuln.js' in index_html
    assert '/assets/fleet-phase3-host-filters.js' in index_html

    orchestrator = (templates_dir / "fleet-phase3-host-filters.js").read_text(encoding="utf-8")
    assert 'phase3HostFiltersUi.initHostFiltersUi' in orchestrator
    assert 'phase3HostFiltersVuln.initHostFiltersVuln' in orchestrator


def test_phase3_vuln_upgrade_status_copy_smoke(templates_dir):
    vuln_js = (templates_dir / "fleet-phase3-host-filters-vuln.js").read_text(encoding="utf-8")

    # CVE flow status lines used by UI and support docs/operators.
    assert 'Running CVE check…' in vuln_js
    assert 'CVE check started (job_id: ' in vuln_js
    assert 'Enter a CVE or a package name.' in vuln_js

    # Upgrade status rendering strings (package mode + CVE mode)
    assert 'Starting CVE upgrade on ' in vuln_js
    assert 'Starting upgrade of ' in vuln_js
    assert 'Selected: ' in vuln_js
    assert 'Run CVE check to see affected packages.' in vuln_js

    # Package tokens from CVE output must be normalized before UI selection/job payload.
    assert 'function normalizePackageToken' in vuln_js
    assert 'j.packages.map(normalizePackageToken).filter(Boolean)' in vuln_js
    assert "const pkgName = normalizePackageToken(pkgEl?.value || '')" in vuln_js
