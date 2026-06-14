import asyncio

from app import terminal_pipe


class FakeClientWebSocket:
    def __init__(self, inbound=None):
        self.inbound = list(inbound or [{"type": "websocket.disconnect"}])
        self.sent_text = []
        self.sent_bytes = []

    async def receive(self):
        if self.inbound:
            return self.inbound.pop(0)
        return {"type": "websocket.disconnect"}

    async def send_text(self, message):
        self.sent_text.append(message)

    async def send_bytes(self, message):
        self.sent_bytes.append(message)


class FakeAgentWebSocket:
    def __init__(self, inbound=None):
        self.inbound = list(inbound or [])
        self.sent = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    def __aiter__(self):
        return self

    async def __anext__(self):
        if not self.inbound:
            raise StopAsyncIteration
        return self.inbound.pop(0)

    async def send(self, message):
        self.sent.append(message)


class HangingAgentWebSocket(FakeAgentWebSocket):
    def __init__(self):
        super().__init__()
        self.exited = False

    async def __aexit__(self, exc_type, exc, tb):
        self.exited = True
        return False

    async def __anext__(self):
        await asyncio.Event().wait()


def test_raw_pipe_encodes_browser_text_as_agent_bytes(monkeypatch):
    agent_ws = FakeAgentWebSocket()
    client_ws = FakeClientWebSocket(
        [
            {"type": "websocket.receive", "text": "imre\r"},
            {"type": "websocket.disconnect"},
        ]
    )

    async def connect(*args, **kwargs):
        return agent_ws

    monkeypatch.setattr(terminal_pipe, "_connect_agent_ws", connect)

    asyncio.run(terminal_pipe.raw_pipe(client_ws, "ws://agent/terminal/ws"))

    assert agent_ws.sent == [b"imre\r"]


def test_raw_pipe_decodes_agent_bytes_to_browser_text(monkeypatch):
    agent_ws = FakeAgentWebSocket([b"Par", b"ool: "])
    client_ws = FakeClientWebSocket()

    async def connect(*args, **kwargs):
        return agent_ws

    monkeypatch.setattr(terminal_pipe, "_connect_agent_ws", connect)

    asyncio.run(terminal_pipe.raw_pipe(client_ws, "ws://agent/terminal/ws"))

    assert client_ws.sent_text == ["Par", "ool: "]
    assert client_ws.sent_bytes == []


def test_raw_pipe_closes_agent_when_browser_disconnects(monkeypatch):
    agent_ws = HangingAgentWebSocket()
    client_ws = FakeClientWebSocket([{"type": "websocket.disconnect"}])

    async def connect(*args, **kwargs):
        return agent_ws

    monkeypatch.setattr(terminal_pipe, "_connect_agent_ws", connect)

    asyncio.run(terminal_pipe.raw_pipe(client_ws, "ws://agent/terminal/ws"))

    assert agent_ws.exited is True


def test_terminal_websocket_origin_must_match_host():
    from app.routers.terminal_ws import _websocket_origin_allowed

    assert _websocket_origin_allowed({"host": "fleet.example.test", "origin": "https://fleet.example.test"})
    assert _websocket_origin_allowed({"host": "fleet.example.test"})
    assert not _websocket_origin_allowed({"host": "fleet.example.test", "origin": "https://evil.example.test"})
