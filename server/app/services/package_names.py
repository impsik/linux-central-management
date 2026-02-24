from __future__ import annotations

import re

_PKG_RE = re.compile(r"^[a-z0-9][a-z0-9+.:~-]*$", re.IGNORECASE)


def normalize_package_token(raw: object) -> str:
    s = str(raw or "").strip()
    if not s:
        return ""
    if (s.startswith("'") and s.endswith("'")) or (s.startswith('"') and s.endswith('"')):
        s = s[1:-1].strip()
    ann_idx = s.find(" (")
    if ann_idx > 0:
        s = s[:ann_idx].strip()
    if any(ch.isspace() for ch in s):
        return ""
    if not s or not _PKG_RE.match(s):
        return ""
    return s


def sanitize_package_list(values: list[object] | None) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for v in values or []:
        n = normalize_package_token(v)
        if not n or n in seen:
            continue
        seen.add(n)
        out.append(n)
    return out
