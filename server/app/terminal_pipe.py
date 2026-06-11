from __future__ import annotations

import asyncio
import logging
from contextlib import suppress
from codecs import getincrementaldecoder
from typing import Any

import websockets

logger = logging.getLogger(__name__)


async def _connect_agent_ws(
    agent_url: str,
    *,
    headers: Any | None = None,
    timeout_s: float = 10.0,
):
    """Connect to the agent websocket with a timeout.

    Returns an *un-entered* websocket connection object.
    """

    return await asyncio.wait_for(
        websockets.connect(
            agent_url,
            ping_interval=None,
            ping_timeout=None,
            additional_headers=headers,
        ),
        timeout=timeout_s,
    )


async def _close_client_ws(client_ws, *, code: int, reason: str, message: str | None = None) -> None:
    with suppress(Exception):
        if message:
            await client_ws.send_text(message)
    with suppress(Exception):
        await client_ws.close(code=code, reason=reason)


async def raw_pipe(client_ws, agent_url: str, headers: Any | None = None, *, allow_input: bool = True) -> None:
    """Pipe bytes/text between browser client and agent.

    If allow_input=False, the client can only *view* output; keystrokes are discarded.
    """

    logger.info("Attempting to connect to agent: %s", agent_url)

    try:
        agent_ws = await _connect_agent_ws(agent_url, headers=headers)
    except asyncio.TimeoutError:
        err = f"Connection timeout to {agent_url}"
        logger.error(err)
        await _close_client_ws(client_ws, code=1008, reason="Connection timeout", message=f"\r\n[ERROR] {err}\r\n")
        return
    except websockets.exceptions.InvalidURI:
        err = f"Invalid agent URL: {agent_url}"
        logger.error(err)
        await _close_client_ws(client_ws, code=1008, reason="Invalid agent URL", message=f"\r\n[ERROR] {err}\r\n")
        return
    except websockets.exceptions.InvalidStatusCode as e:
        err = f"Agent connection failed with status {e.status_code}: {agent_url}"
        logger.error(err)
        await _close_client_ws(
            client_ws,
            code=1008,
            reason=f"Agent connection failed: {e.status_code}",
            message=f"\r\n[ERROR] {err}\r\n",
        )
        return
    except (ConnectionRefusedError, OSError) as e:
        err = f"Cannot connect to agent at {agent_url}: {e}"
        logger.error(err, exc_info=True)
        await _close_client_ws(
            client_ws,
            code=1008,
            reason=f"Connection refused: {e}",
            message=f"\r\n[ERROR] {err}\r\n",
        )
        return
    except Exception as e:
        err = f"Error connecting to agent {agent_url}: {e}"
        logger.error(err, exc_info=True)
        await _close_client_ws(
            client_ws,
            code=1011,
            reason=f"Connection error: {e}",
            message=f"\r\n[ERROR] {err}\r\n",
        )
        return

    logger.info("Successfully connected to agent: %s", agent_url)

    async with agent_ws:
        agent_output_decoder = getincrementaldecoder("utf-8")("replace")

        async def c2a() -> None:
            try:
                while True:
                    msg = await client_ws.receive()
                    if msg.get("type") == "websocket.disconnect":
                        break
                    if not allow_input:
                        continue
                    if msg.get("bytes") is not None:
                        await agent_ws.send(msg["bytes"])
                    elif msg.get("text") is not None:
                        await agent_ws.send(msg["text"].encode("utf-8"))
            except (websockets.exceptions.ConnectionClosed, ConnectionError):
                logger.info("Client WebSocket closed")
            except Exception as e:
                logger.error("Error forwarding client to agent: %s", e, exc_info=True)

        async def a2c() -> None:
            try:
                async for msg in agent_ws:
                    if isinstance(msg, bytes):
                        text = agent_output_decoder.decode(msg)
                        if text:
                            await client_ws.send_text(text)
                    else:
                        await client_ws.send_text(msg)
                remaining = agent_output_decoder.decode(b"", final=True)
                if remaining:
                    await client_ws.send_text(remaining)
            except (websockets.exceptions.ConnectionClosed, ConnectionError):
                logger.info("Agent WebSocket closed")
            except Exception as e:
                logger.error("Error forwarding agent to client: %s", e, exc_info=True)

        tasks = {asyncio.create_task(c2a()), asyncio.create_task(a2c())}
        try:
            done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            for task in done:
                exc = task.exception()
                if exc:
                    logger.error("Pipe task raised: %s", exc, exc_info=True)
            for task in pending:
                task.cancel()
            if pending:
                await asyncio.gather(*pending, return_exceptions=True)
        finally:
            for task in tasks:
                if not task.done():
                    task.cancel()
