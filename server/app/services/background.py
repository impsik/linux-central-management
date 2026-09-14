from __future__ import annotations

import asyncio
from collections.abc import Callable
from typing import ParamSpec, TypeVar

P = ParamSpec("P")
T = TypeVar("T")


async def run_blocking(func: Callable[P, T], *args: P.args, **kwargs: P.kwargs) -> T:
    """Run blocking work off the event loop, joining the worker on cancellation.

    Cancelling an asyncio task cannot stop its thread. Wait for that thread before
    callers clean up its files/resources or start another copy of the same job.
    """
    worker = asyncio.create_task(asyncio.to_thread(func, *args, **kwargs))
    try:
        return await asyncio.shield(worker)
    except asyncio.CancelledError:
        while not worker.done():
            try:
                await asyncio.shield(worker)
            except asyncio.CancelledError:
                continue
            except Exception:
                break
        # Cancellation wins over a late worker exception; retrieve it so it does
        # not become an unhandled task exception during shutdown.
        if not worker.cancelled():
            worker.exception()
        raise
