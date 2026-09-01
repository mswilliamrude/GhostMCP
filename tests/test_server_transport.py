"""Tests for the HTTP/WS/SSE server transports built by build_server_app().

These exercise the exact Starlette app the deployed container serves in
GHOST_MODE=server, covering the two transports remote MCP clients use:
  - WebSocket (/ws)  — bidirectional JSON-RPC, with 'mcp' subprotocol echo
  - SSE (/sse + /mcp) — session handshake then POST, reply via the SSE stream
plus the /health and /healthz liveness endpoints.
"""

from __future__ import annotations

import json

import pytest
from starlette.testclient import TestClient

from ghostmcp.mcp import build_server_app


@pytest.fixture()
def client() -> TestClient:
    return TestClient(build_server_app())


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

class TestHealth:
    def test_health_ok(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "healthy"
        assert "tools" in body

    def test_healthz_alias_ok(self, client):
        """/healthz must work too — probes commonly hit this path."""
        resp = client.get("/healthz")
        assert resp.status_code == 200
        assert resp.json()["status"] == "healthy"


# ---------------------------------------------------------------------------
# WebSocket transport
# ---------------------------------------------------------------------------

class TestWebSocketTransport:
    def test_ws_tools_list_roundtrip(self, client):
        with client.websocket_connect("/ws") as ws:
            ws.send_text(json.dumps({
                "jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {},
            }))
            reply = json.loads(ws.receive_text())
        assert reply["id"] == 1
        assert "result" in reply
        assert isinstance(reply["result"]["tools"], list)
        assert len(reply["result"]["tools"]) > 0

    def test_ws_echoes_mcp_subprotocol(self, client):
        """A client offering the 'mcp' subprotocol must get it echoed back,
        otherwise the handshake aborts on strict clients."""
        with client.websocket_connect("/ws", subprotocols=["mcp"]) as ws:
            assert ws.accepted_subprotocol == "mcp"

    def test_ws_no_subprotocol_still_connects(self, client):
        """Clients that offer no subprotocol must still connect."""
        with client.websocket_connect("/ws") as ws:
            assert ws.accepted_subprotocol in (None, "")

    def test_ws_initialize(self, client):
        with client.websocket_connect("/ws") as ws:
            ws.send_text(json.dumps({
                "jsonrpc": "2.0", "id": 7, "method": "initialize", "params": {},
            }))
            reply = json.loads(ws.receive_text())
        assert reply["id"] == 7
        assert reply["result"]["protocolVersion"]
        assert reply["result"]["serverInfo"]["name"] == "GhostMCP"

    def test_ws_parse_error(self, client):
        with client.websocket_connect("/ws") as ws:
            ws.send_text("this is not json{")
            reply = json.loads(ws.receive_text())
        assert reply["error"]["code"] == -32700


# ---------------------------------------------------------------------------
# SSE transport
# ---------------------------------------------------------------------------

class TestSSETransport:
    """SSE handshake tests.

    The SSE stream is intentionally long-lived (infinite keep-alive), which
    deadlocks Starlette's threaded TestClient on teardown. So instead of the
    TestClient we drive the ASGI app directly with a controllable receive
    channel and inject an http.disconnect to end the stream deterministically.
    """

    @staticmethod
    async def _drive_sse(app, path, to_send=None, disconnect_after_blocks=1):
        """Run the ASGI app for an SSE GET, collect body chunks, then
        disconnect. Returns the decoded text captured before disconnect.

        `to_send`: optional coroutine(app_state) -> None run after the first
        block is received (used to POST a message mid-stream).
        """
        import anyio

        scope = {
            "type": "http",
            "http_version": "1.1",
            "method": "GET",
            "path": path,
            "headers": [],
            "query_string": b"",
            "client": ("127.0.0.1", 12345),
            "server": ("testserver", 80),
            "scheme": "http",
        }

        captured: list[str] = []
        blocks_seen = 0
        disconnect_event = anyio.Event()

        async def receive():
            # First deliver nothing special; once told, send a disconnect.
            await disconnect_event.wait()
            return {"type": "http.disconnect"}

        async def send(message):
            nonlocal blocks_seen
            if message["type"] == "http.response.body":
                body = message.get("body", b"")
                if body:
                    captured.append(body.decode("utf-8", "replace"))
                    if body.endswith(b"\n\n"):
                        blocks_seen += 1
                        if blocks_seen >= disconnect_after_blocks:
                            disconnect_event.set()

        await app(scope, receive, send)
        return "".join(captured)

    def test_sse_yields_endpoint_event(self, client):
        """GET /sse must first emit the 'endpoint' event carrying the
        session-scoped /mcp URL the client should POST to."""
        import anyio

        app = build_server_app()
        text = anyio.run(self._drive_sse, app, "/sse")
        assert "event: endpoint" in text
        assert "/mcp?session_id=" in text

    def test_post_without_session_rejected(self, client):
        """POST /mcp without a valid session_id is a handshake violation."""
        resp = client.post(
            "/mcp",
            content=json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}),
        )
        assert resp.status_code == 400
        assert "session" in resp.json()["error"].lower()

    def test_post_with_bogus_session_rejected(self, client):
        resp = client.post(
            "/mcp?session_id=does-not-exist",
            content=json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}),
        )
        assert resp.status_code == 400

    def test_sse_full_handshake_and_call(self):
        """End-to-end remote-MCP handshake against a REAL server socket.

        In-process ASGI transports serialize requests, so a streaming GET
        blocks a concurrent POST — which cannot model the SSE two-channel
        flow. We therefore spin a real uvicorn server on an ephemeral port,
        open /sse, POST to /mcp?session_id=..., and read the reply off the
        stream. Skips gracefully if a server socket can't be bound.
        """
        import socket
        import threading
        import time

        import httpx
        import uvicorn

        app = build_server_app()

        # Pick a free port.
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()

        config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error")
        server = uvicorn.Server(config)
        thread = threading.Thread(target=server.run, daemon=True)
        thread.start()

        try:
            # Wait for startup (up to ~5s).
            base = f"http://127.0.0.1:{port}"
            for _ in range(50):
                if server.started:
                    break
                time.sleep(0.1)
            else:
                pytest.skip("uvicorn did not start in time")

            with httpx.Client(base_url=base, timeout=10.0) as c:
                with c.stream("GET", "/sse") as resp:
                    assert resp.status_code == 200
                    session_id = None
                    payload = None
                    posted = False
                    for line in resp.iter_lines():
                        if not line.startswith("data:"):
                            continue
                        data = line[len("data:"):].strip()
                        if not posted and "session_id=" in data:
                            session_id = data.split("session_id=", 1)[1].strip()
                            post = c.post(
                                f"/mcp?session_id={session_id}",
                                content=json.dumps({
                                    "jsonrpc": "2.0", "id": 42,
                                    "method": "tools/list", "params": {},
                                }),
                            )
                            assert post.status_code == 202
                            posted = True
                            continue
                        if posted and data and not data.startswith("keep-alive"):
                            payload = json.loads(data)
                            break
                    resp.close()

            assert session_id, "no session_id delivered by /sse"
            assert payload is not None, "no JSON-RPC reply received over SSE"
            assert payload["id"] == 42
            assert "result" in payload
            assert isinstance(payload["result"]["tools"], list)
        finally:
            server.should_exit = True
            thread.join(timeout=5)
