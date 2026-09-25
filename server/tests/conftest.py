import os
import sys
from pathlib import Path

import pytest

# Ensure the server/ directory is on sys.path so `import app.*` works in all runners.
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# Test-suite guardrails:
# CI workflow exports production-like env defaults globally for backend jobs.
# SQLite tests in this suite require local in-memory bootstrap behavior instead.
os.environ["DB_AUTO_CREATE_TABLES"] = "true"
os.environ["DB_REQUIRE_MIGRATIONS_UP_TO_DATE"] = "false"
os.environ["AGENT_SHARED_TOKEN"] = ""
os.environ["ALLOW_INSECURE_NO_AGENT_TOKEN"] = "true"
os.environ["SERVER_BIND_HOST"] = "127.0.0.1"
os.environ["HIGH_RISK_APPROVAL_ENABLED"] = "false"


@pytest.fixture(autouse=True)
def disable_automatic_cve_jobs(monkeypatch):
    # Explicit CVE tests call the workers directly or override these settings.
    # Unrelated API tests must not contact feeds/send email or concurrently reuse
    # SQLite StaticPool's single connection for background report transactions.
    monkeypatch.setenv("CVE_SYNC_ENABLED", "false")
    monkeypatch.setenv("CVE_REPORTING_ENABLED", "false")
    # Some test modules import app.config during collection; others reload app.*
    # after setting their environment. Cover both without importing the app here.
    config = sys.modules.get("app.config")
    if config is not None:
        monkeypatch.setattr(config.settings, "cve_sync_enabled", False)
        monkeypatch.setattr(config.settings, "cve_reporting_enabled", False)
