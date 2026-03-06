#!/usr/bin/env python3
"""Lightweight audit for hardcoded theme colors in server UI templates."""

from __future__ import annotations

import re
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]

TARGETS = [
    REPO_ROOT / "server/app/templates",
    REPO_ROOT / "server/app/routers/reports_html.py",
]

PATTERNS = [
    (
        "inline-style-hex",
        re.compile(r"""style\s*=\s*(["'])[^"']*#(?:[0-9a-fA-F]{3}|[0-9a-fA-F]{6}|[0-9a-fA-F]{8})[^"']*\1"""),
    ),
    (
        "js-color-assignment-hex",
        re.compile(
            r"""(?:strokeStyle|fillStyle|background|foreground|cursor|selection|black|red|green|yellow|blue|magenta|cyan|white|brightBlack|brightRed|brightGreen|brightYellow|brightBlue|brightMagenta|brightCyan|brightWhite)\s*[:=]\s*["']#(?:[0-9a-fA-F]{3}|[0-9a-fA-F]{6}|[0-9a-fA-F]{8})["']"""
        ),
    ),
]

XTERM_ALLOWLIST = {
    "background",
    "foreground",
    "cursor",
    "selection",
    "black",
    "red",
    "green",
    "yellow",
    "blue",
    "magenta",
    "cyan",
    "white",
    "brightBlack",
    "brightRed",
    "brightGreen",
    "brightYellow",
    "brightBlue",
    "brightMagenta",
    "brightCyan",
    "brightWhite",
}


def iter_files() -> list[Path]:
    files: list[Path] = []
    for target in TARGETS:
        if target.is_file():
            files.append(target)
            continue
        files.extend(
            p
            for p in target.rglob("*")
            if p.is_file() and p.suffix in {".html", ".js", ".py"}
        )
    return sorted(files)


def is_allowlisted(path: Path, line: str) -> bool:
    rel = path.relative_to(REPO_ROOT).as_posix()
    if rel != "server/app/templates/index.html":
        return False
    stripped = line.strip()
    for key in XTERM_ALLOWLIST:
        if stripped.startswith(f"{key}: '#"):
            return True
    return False


def main() -> int:
    findings: list[tuple[str, int, str, str]] = []
    for path in iter_files():
        rel = path.relative_to(REPO_ROOT).as_posix()
        text = path.read_text(encoding="utf-8")
        for lineno, line in enumerate(text.splitlines(), start=1):
            if is_allowlisted(path, line):
                continue
            for label, pattern in PATTERNS:
                if pattern.search(line):
                    findings.append((rel, lineno, label, line.strip()))

    if findings:
        print("Theme audit failed: hardcoded colors found.\n")
        for rel, lineno, label, line in findings:
            print(f"{rel}:{lineno}: {label}: {line}")
        return 1

    print("Theme audit passed: no risky hardcoded template colors found.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
