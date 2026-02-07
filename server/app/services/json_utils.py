from __future__ import annotations

import json
from typing import Any


def loads_or(value: str | None, default: Any) -> Any:
    if not value:
        return default
    try:
        return json.loads(value)
    except Exception:
        return default
