#!/usr/bin/env python3
"""
GhostMCP Local Connectivity Bridge
====================================

Runs on the developer's machine. Connects outbound to GhostMCP via WebSocket
and provides GhostMCP tools with access to local services for webapp testing.

Usage:
    python3 ghost_bridge.py --connect ws://10.0.10.7:8080/bridge --ports 8080,3000
    python3 ghost_bridge.py --connect ws://localhost:8080/bridge --ports 8080

The bridge:
1. Connects to GhostMCP via WebSocket (outbound — works through NAT/firewalls)
2. Registers which localhost ports are available for testing
3. Receives HTTP fetch requests from GhostMCP tools
4. Makes the request locally (httpx)
5. Returns the response through the WebSocket

No inbound ports required. Works with any MCP client (opencode, Cursor, VS Code).

See docs/design/LOCAL_CONNECTIVITY_BRIDGE.md for full design.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import signal
import sys
import time
from typing import Optional

try:
    import httpx
except ImportError:
    print("ERROR: httpx required. Install with: pip install httpx")
    sys.exit(1)

try:
    import websockets
except ImportError:
    print("ERROR: websockets required. Install with: pip install websockets")
    sys.exit(1)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [bridge] %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("ghost_bridge")


class GhostBridge:
    """Local connectivity bridge for GhostMCP webapp testing."""

    def __init__(self, server_url: str, ports: list[int], client_id: str = ""):
        self.server_url = server_url
        self.ports = ports
        self.client_id = client_id or f"bridge-{int(time.time())}"
        self.ws: Optional[websockets.WebSocketClientProtocol] = None
        self.running = False
        self._http_client: Optional[httpx.AsyncClient] = None

    async def start(self):
        """Connect to GhostMCP, register ports, and start handling requests."""
        self.running = True
        self._http_client = httpx.AsyncClient(timeout=30.0, follow_redirects=True)

        backoff = 5
        max_backoff = 30

        while self.running:
            try:
                log.info(f"Connecting to {self.server_url}...")
                async with websockets.connect(
                    self.server_url,
                    additional_headers={"X-Client-ID": self.client_id},
                    ping_interval=20,
                    ping_timeout=10,
                    close_timeout=5,
                ) as ws:
                    self.ws = ws
                    backoff = 5  # Reset on successful connect

                    # Register available ports
                    await self._register(ws)

                    # Handle messages until disconnect
                    await self._message_loop(ws)

            except websockets.ConnectionClosed as e:
                log.warning(f"Connection closed: {e}")
            except ConnectionRefusedError:
                log.warning(f"Connection refused — is GhostMCP running at {self.server_url}?")
            except Exception as e:
                log.error(f"Connection error: {type(e).__name__}: {e}")

            if not self.running:
                break

            log.info(f"Reconnecting in {backoff}s...")
            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, max_backoff)

        if self._http_client:
            await self._http_client.aclose()

    async def _register(self, ws):
        """Send port registration message to GhostMCP."""
        msg = json.dumps({
            "type": "register",
            "client_id": self.client_id,
            "ports": self.ports,
        })
        await ws.send(msg)
        log.info(f"Registered ports {self.ports} as '{self.client_id}'")

        # Wait for acknowledgment
        try:
            resp = await asyncio.wait_for(ws.recv(), timeout=5)
            data = json.loads(resp)
            if data.get("type") == "registered":
                log.info(f"GhostMCP acknowledged: {data.get('ports', [])}")
            else:
                log.warning(f"Unexpected response: {data}")
        except asyncio.TimeoutError:
            log.warning("No acknowledgment from GhostMCP (continuing anyway)")

    async def _message_loop(self, ws):
        """Process incoming messages from GhostMCP."""
        async for raw in ws:
            try:
                msg = json.loads(raw)
            except json.JSONDecodeError:
                log.warning(f"Invalid JSON received: {raw[:100]}")
                continue

            msg_type = msg.get("type", "")

            if msg_type == "request":
                # GhostMCP wants us to fetch something locally
                asyncio.create_task(self._handle_request(ws, msg))
            elif msg_type == "heartbeat_ack":
                pass  # Expected
            else:
                log.debug(f"Unknown message type: {msg_type}")

    async def _handle_request(self, ws, msg: dict):
        """Fetch a URL locally and return the response through the WebSocket."""
        req_id = msg.get("id", "unknown")
        method = msg.get("method", "GET").upper()
        url = msg.get("url", "")
        headers = msg.get("headers", {})
        body = msg.get("body")

        log.info(f"[{req_id}] {method} {url}")

        try:
            # Make the request locally
            resp = await self._http_client.request(
                method=method,
                url=url,
                headers=headers,
                content=body.encode() if body else None,
            )

            # Build response
            response = {
                "type": "response",
                "id": req_id,
                "status": resp.status_code,
                "headers": dict(resp.headers),
                "body": resp.text,
            }

            log.info(f"[{req_id}] → {resp.status_code} ({len(resp.text)} chars)")

        except httpx.ConnectError as e:
            response = {
                "type": "error",
                "id": req_id,
                "error": f"Connection refused: {e}",
            }
            log.error(f"[{req_id}] → Connection refused: {url}")

        except httpx.TimeoutException:
            response = {
                "type": "error",
                "id": req_id,
                "error": f"Timeout fetching {url}",
            }
            log.error(f"[{req_id}] → Timeout: {url}")

        except Exception as e:
            response = {
                "type": "error",
                "id": req_id,
                "error": f"{type(e).__name__}: {e}",
            }
            log.error(f"[{req_id}] → Error: {e}")

        try:
            await ws.send(json.dumps(response))
        except Exception:
            log.error(f"[{req_id}] Failed to send response — connection lost")

    async def shutdown(self):
        """Graceful shutdown."""
        log.info("Shutting down...")
        self.running = False
        if self.ws:
            try:
                await self.ws.close()
            except Exception:
                pass


def main():
    parser = argparse.ArgumentParser(
        description="GhostMCP Local Connectivity Bridge — test local webapps with GhostMCP",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --connect ws://localhost:8080/bridge --ports 8080,3000
  %(prog)s --connect ws://10.0.10.7:8080/bridge --ports 8080
  %(prog)s --connect ws://10.0.10.7:8080/bridge --ports 8080,3000,5173 --id my-laptop
        """,
    )
    parser.add_argument(
        "--connect", required=True,
        help="GhostMCP WebSocket URL (e.g. ws://10.0.10.7:8080/bridge)",
    )
    parser.add_argument(
        "--ports", required=True,
        help="Comma-separated localhost ports to make available (e.g. 8080,3000)",
    )
    parser.add_argument(
        "--id", default="",
        help="Client identifier (default: auto-generated)",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true",
        help="Enable debug logging",
    )

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    ports = [int(p.strip()) for p in args.ports.split(",") if p.strip()]
    if not ports:
        print("ERROR: No valid ports specified")
        sys.exit(1)

    bridge = GhostBridge(
        server_url=args.connect,
        ports=ports,
        client_id=args.id,
    )

    loop = asyncio.new_event_loop()

    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, lambda: asyncio.ensure_future(bridge.shutdown()))

    try:
        loop.run_until_complete(bridge.start())
    except KeyboardInterrupt:
        loop.run_until_complete(bridge.shutdown())
    finally:
        loop.close()


if __name__ == "__main__":
    main()
