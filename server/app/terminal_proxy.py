"""Deprecated.

This was an older text-only websocket proxy.
The active implementation is `server/app/terminal_pipe.py`.

Kept for now to avoid breaking any external imports; safe to delete once unused.
"""

import asyncio

import websockets


async def pipe(ws_client, agent_url: str) -> None:
    async with websockets.connect(agent_url, ping_interval=None) as ws_agent:

        async def c2a() -> None:
            async for m in ws_client.iter_text():
                await ws_agent.send(m)

        async def a2c() -> None:
            async for m in ws_agent:
                await ws_client.send_text(m)

        await asyncio.gather(c2a(), a2c())
