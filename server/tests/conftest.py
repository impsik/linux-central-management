import sys
from pathlib import Path

# Ensure the server/ directory is on sys.path so `import app.*` works in all runners.
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
