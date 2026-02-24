from app.services.package_names import normalize_package_token, sanitize_package_list


def test_normalize_package_token_strips_display_annotations():
    raw = "apport (installed:2.28.1-0ubuntu3.1 < fixed:0:2.28.1-0ubuntu3.6)"
    assert normalize_package_token(raw) == "apport"


def test_sanitize_package_list_drops_invalid_and_dedupes():
    vals = [
        "apport (installed:2.28.1-0ubuntu3.1 < fixed:0:2.28.1-0ubuntu3.6)",
        "openssl",
        "openssl ",
        "not valid token !!!",
        "",
    ]
    assert sanitize_package_list(vals) == ["apport", "openssl"]
