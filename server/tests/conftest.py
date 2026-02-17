import os
import sys
from pathlib import Path

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
