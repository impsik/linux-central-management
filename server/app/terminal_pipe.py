from __future__ import annotations

import asyncio
import logging
from contextlib import suppress
from typing import Any

import websockets

logger = logging.getLogger(__name__)


def _candidate_agent_urls(agent_url: str) -> list[str]:
    urls = [agent_url]
    if agent_url.startswith("wss://"):
        urls.append("ws://" + agent_url[len("wss://") :])
    return urls


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

    candidate_urls = _candidate_agent_urls(agent_url)
    logger.info("Attempting to connect to agent: %s (candidates=%s)", agent_url, candidate_urls)

    agent_ws = None
    last_error: Exception | None = None
    for attempt_url in candidate_urls:
        try:
            agent_ws = await _connect_agent_ws(attempt_url, headers=headers)
            agent_url = attempt_url
            break
        except asyncio.TimeoutError as e:
            last_error = e
            if attempt_url != candidate_urls[-1]:
                logger.warning("Agent terminal connect timeout via %s; trying fallback if available", attempt_url)
                continue
            err = f"Connection timeout to {attempt_url}"
            logger.error(err)
            await _close_client_ws(client_ws, code=1008, reason="Connection timeout", message=f"\r\n[ERROR] {err}\r\n")
            return
        except websockets.InvalidURI as e:
            last_error = e
            err = f"Invalid agent URL: {attempt_url}"
            logger.error(err)
            await _close_client_ws(client_ws, code=1008, reason="Invalid agent URL", message=f"\r\n[ERROR] {err}\r\n")
            return
        except websockets.InvalidStatusCode as e:
            last_error = e
            if attempt_url != candidate_urls[-1]:
                logger.warning("Agent terminal connect via %s returned status %s; trying fallback if available", attempt_url, e.status_code)
                continue
            err = f"Agent connection failed with status {e.status_code}: {attempt_url}"
            logger.error(err)
            await _close_client_ws(
                client_ws,
                code=1008,
                reason=f"Agent connection failed: {e.status_code}",
                message=f"\r\n[ERROR] {err}\r\n",
            )
            return
        except (ConnectionRefusedError, OSError) as e:
            last_error = e
            if attempt_url != candidate_urls[-1]:
                logger.warning("Agent terminal connect via %s failed (%s); trying fallback if available", attempt_url, e)
                continue
            err = f"Cannot connect to agent at {attempt_url}: {e}"
            logger.error(err, exc_info=True)
            await _close_client_ws(
                client_ws,
                code=1008,
                reason=f"Connection refused: {e}",
                message=f"\r\n[ERROR] {err}\r\n",
            )
            return
        except Exception as e:
            last_error = e
            if attempt_url != candidate_urls[-1]:
                logger.warning("Agent terminal connect via %s failed unexpectedly (%s); trying fallback if available", attempt_url, e)
                continue
            err = f"Error connecting to agent {attempt_url}: {e}"
            logger.error(err, exc_info=True)
            await _close_client_ws(
                client_ws,
                code=1011,
                reason=f"Connection error: {e}",
                message=f"\r\n[ERROR] {err}\r\n",
            )
            return

    if agent_ws is None:
        err = f"Cannot connect to agent at {agent_url}: {last_error or 'unknown error'}"
        logger.error(err)
        await _close_client_ws(client_ws, code=1008, reason="Connection refused", message=f"\r\n[ERROR] {err}\r\n")
        return

    logger.info("Successfully connected to agent: %s", agent_url)

    async with agent_ws:

        async def c2a() -> None:
            try:
                async for msg in client_ws.iter_bytes():
                    if allow_input:
                        await agent_ws.send(msg)
                    # else: discard input
            except (websockets.ConnectionClosed, ConnectionError):
                logger.info("Client WebSocket closed")
            except Exception as e:
                logger.error("Error forwarding client to agent: %s", e, exc_info=True)

        async def a2c() -> None:
            try:
                async for msg in agent_ws:
                    if isinstance(msg, bytes):
                        await client_ws.send_bytes(msg)
                    else:
                        await client_ws.send_text(msg)
            except (websockets.ConnectionClosed, ConnectionError):
                logger.info("Agent WebSocket closed")
            except Exception as e:
                logger.error("Error forwarding agent to client: %s", e, exc_info=True)

        results = await asyncio.gather(c2a(), a2c(), return_exceptions=True)
        for r in results:
            if isinstance(r, Exception):
                logger.error("Pipe task raised: %s", r, exc_info=True)
