from app.routers.search import release_key_for_host
from app.services.rpm_version import is_vulnerable


def test_release_key_for_rpm_hosts():
    assert release_key_for_host("rocky", "9.4") == "rocky-9"
    assert release_key_for_host("fedora", "40") == "fedora-40"


def test_rpm_version_compare_handles_epoch_and_release():
    assert is_vulnerable("1:3.2.2-5.el9", "1:3.2.2-6.el9") is True
    assert is_vulnerable("1:3.2.2-7.el9", "1:3.2.2-6.el9") is False
