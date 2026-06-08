import re


def _split_epoch(version: str) -> tuple[int, str]:
    if ":" not in version:
        return 0, version
    epoch, rest = version.split(":", 1)
    try:
        return int(epoch), rest
    except ValueError:
        return 0, rest


def _segments(value: str) -> list[str]:
    return re.findall(r"[A-Za-z]+|\d+|~|\^", value or "")


def compare_versions(v1: str, v2: str) -> int:
    """
    Small RPM-like version comparator for server-side CVE filtering.
    Returns -1 when v1 < v2, 0 when equal, 1 when v1 > v2.
    """
    e1, rest1 = _split_epoch(v1 or "")
    e2, rest2 = _split_epoch(v2 or "")
    if e1 != e2:
        return -1 if e1 < e2 else 1

    s1 = _segments(rest1)
    s2 = _segments(rest2)
    i = 0
    while i < len(s1) or i < len(s2):
        a = s1[i] if i < len(s1) else ""
        b = s2[i] if i < len(s2) else ""
        if a == b:
            i += 1
            continue
        if a == "~" or b == "^":
            return -1
        if b == "~" or a == "^":
            return 1
        if not a:
            return -1
        if not b:
            return 1
        if a.isdigit() and b.isdigit():
            ai = int(a.lstrip("0") or "0")
            bi = int(b.lstrip("0") or "0")
            if ai != bi:
                return -1 if ai < bi else 1
            if len(a.lstrip("0")) != len(b.lstrip("0")):
                return -1 if len(a.lstrip("0")) < len(b.lstrip("0")) else 1
        elif a.isdigit():
            return 1
        elif b.isdigit():
            return -1
        else:
            return -1 if a < b else 1
        i += 1
    return 0


def is_vulnerable(installed_version: str, fixed_version: str) -> bool:
    return compare_versions(installed_version, fixed_version) < 0
