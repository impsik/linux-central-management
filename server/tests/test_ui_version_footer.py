from types import SimpleNamespace


def test_sidebar_version_footer_is_rendered():
    from app.routers import ui
    from app.version import APP_VERSION

    request = SimpleNamespace(state=SimpleNamespace(csp_nonce=None))
    html = ui._render_template_with_nonce("index.html", request)

    assert "__APP_VERSION__" not in html
    assert 'class="fleet-app-version"' in html
    assert f"Version: {APP_VERSION}" in html
