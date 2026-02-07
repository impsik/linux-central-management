from __future__ import annotations


def truncate(text: str | None, max_chars: int) -> str | None:
    if text is None:
        return None
    if max_chars <= 0:
        return ""
    if len(text) <= max_chars:
        return text
    # Keep head+tail for debugging
    head = max_chars // 2
    tail = max_chars - head - 80
    if tail < 0:
        tail = 0
    if tail:
        return text[:head] + "\n\n... [TRUNCATED] ...\n\n" + text[-tail:]
    return text[: max_chars - 40] + "\n\n... [TRUNCATED] ...\n"
