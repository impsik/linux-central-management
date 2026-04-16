import asyncio

from app import terminal_pipe


class _DummyClientWS:
    def __init__(self):
        self.sent_text = []
        self.closed = None

    async def send_text(self, text):
        self.sent_text.append(text)

    async def close(self, code=None, reason=None):
        self.closed = (code, reason)

    async def iter_bytes(self):
        if False:
            yield b""

    async def send_bytes(self, data):
        return None


class _DummyAgentWS:
    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    def __aiter__(self):
        return self

    async def __anext__(self):
        raise StopAsyncIteration

    async def send(self, msg):
        return None


def test_candidate_agent_urls_prefers_configured_scheme_but_adds_ws_fallback_for_wss():
    assert terminal_pipe._candidate_agent_urls("ws://10.0.0.2:18080/terminal/ws") == [
        "ws://10.0.0.2:18080/terminal/ws"
    ]
    assert terminal_pipe._candidate_agent_urls("wss://10.0.0.2:18080/terminal/ws") == [
        "wss://10.0.0.2:18080/terminal/ws",
        "ws://10.0.0.2:18080/terminal/ws",
    ]



def test_raw_pipe_falls_back_from_wss_to_ws(monkeypatch):
    attempts = []

    async def fake_connect(url, *, headers=None, timeout_s=10.0):
        attempts.append(url)
        if url.startswith("wss://"):
            raise OSError("[SSL] record layer failure")
        return _DummyAgentWS()

    monkeypatch.setattr(terminal_pipe, "_connect_agent_ws", fake_connect)

    client_ws = _DummyClientWS()
    asyncio.run(
        terminal_pipe.raw_pipe(
            client_ws,
            "wss://192.168.100.174:18080/terminal/ws",
            headers={"X-Fleet-Terminal-Token": "token"},
        )
    )

    assert attempts == [
        "wss://192.168.100.174:18080/terminal/ws",
        "ws://192.168.100.174:18080/terminal/ws",
    ]
    assert client_ws.closed is None
    assert client_ws.sent_text == []
