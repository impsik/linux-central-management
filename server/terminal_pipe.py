"""Backwards-compatible shim.

The active implementation lives in `server/app/terminal_pipe.py`.
This module remains to avoid breaking older imports.
"""

from app.terminal_pipe import raw_pipe  # noqa: F401
