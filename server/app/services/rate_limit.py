from __future__ import annotations

import time
from dataclasses import dataclass


@dataclass
class RateLimitResult:
    allowed: bool
    retry_after_seconds: int
    remaining: int


class FixedWindowRateLimiter:
    """A tiny in-memory rate limiter (single-process).

    Good enough for LAN MVP and a single uvicorn worker.
    """

    def __init__(self, *, limit: int, window_seconds: int):
        self.limit = int(limit)
        self.window_seconds = int(window_seconds)
        # key -> (window_start_epoch, count)
        self._buckets: dict[str, tuple[int, int]] = {}

    def check(self, key: str) -> RateLimitResult:
        now = int(time.time())
        window_start = now - (now % self.window_seconds)

        prev = self._buckets.get(key)
        if not prev or prev[0] != window_start:
            self._buckets[key] = (window_start, 1)
            return RateLimitResult(True, 0, self.limit - 1)

        count = prev[1]
        if count >= self.limit:
            retry_after = (window_start + self.window_seconds) - now
            return RateLimitResult(False, max(1, retry_after), 0)

        self._buckets[key] = (window_start, count + 1)
        return RateLimitResult(True, 0, self.limit - (count + 1))

    def cleanup(self, *, max_age_seconds: int | None = None) -> None:
        # Best-effort: prevent unbounded growth.
        now = int(time.time())
        max_age = int(max_age_seconds or (self.window_seconds * 10))
        cutoff = now - max_age
        for k, (ws, _c) in list(self._buckets.items()):
            if ws < cutoff:
                self._buckets.pop(k, None)
