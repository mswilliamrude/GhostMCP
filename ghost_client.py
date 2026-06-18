#!/usr/bin/env python3
"""
GhostMCP Local Connectivity Bridge
====================================

Runs on the developer's machine. Connects outbound to GhostMCP via WebSocket
and provides GhostMCP tools with access to local services and optionally
internet connectivity for web research.

Usage:
    # With config file (recommended):
    python3 ghost_client.py --config ~/.ghost_client.yaml

    # Quick CLI mode (no config file):
    python3 ghost_client.py --connect ws://10.0.10.7:8080/bridge --ports 8080,3000

Config file (~/.ghost_client.yaml):
    server: ws://10.0.10.7:8080/bridge
    client_id: my-laptop
    ports:
      - 8080
      - 3000
    allow_web_access: true
    web_access_mode: self_only   # false | self_only | shared
    locality:
      region: US-TX
      timezone: US/Central
      label: "Austin office"

The bridge monitors the config file for changes — edit ports or settings
without restarting. See docs/design/DISTRIBUTED_BRIDGE_NETWORK.md for details.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import signal
import sys
import time
from pathlib import Path
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

try:
    import yaml
except ImportError:
    yaml = None  # Optional — config file requires PyYAML

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [bridge] %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("ghost_client")


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

class BridgeConfig:
    """Bridge configuration from YAML file or CLI args."""

    def __init__(self):
        self.server_url: str = ""
        self.client_id: str = ""
        self.ports: list[int] = []
        self.allow_web_access: bool = False
        self.web_access_mode: str = "false"  # false | self_only | shared
        self.locality: dict = {}
        self._config_path: Optional[str] = None
        self._last_mtime: float = 0

    @classmethod
    def from_cli(cls, server: str, ports: list[int], client_id: str = "") -> BridgeConfig:
        """Create config from CLI arguments."""
        cfg = cls()
        cfg.server_url = server
        cfg.ports = ports
        cfg.client_id = client_id or f"bridge-{int(time.time())}"
        return cfg

    @classmethod
    def from_file(cls, path: str) -> BridgeConfig:
        """Load config from YAML file."""
        if yaml is None:
            print("ERROR: PyYAML required for config files. Install with: pip install pyyaml")
            sys.exit(1)

        cfg = cls()
        cfg._config_path = path
        cfg._reload()
        return cfg

    def _reload(self) -> bool:
        """Reload config from file. Returns True if config changed."""
        if not self._config_path or not os.path.exists(self._config_path):
            return False

        mtime = os.path.getmtime(self._config_path)
        if mtime == self._last_mtime:
            return False

        self._last_mtime = mtime

        with open(self._config_path) as f:
            data = yaml.safe_load(f) or {}

        old_ports = self.ports[:]
        old_web = self.allow_web_access
        old_mode = self.web_access_mode

        self.server_url = data.get("server", self.server_url)
        self.client_id = data.get("client_id", self.client_id or f"bridge-{int(time.time())}")
        self.ports = [int(p) for p in data.get("ports", [])]
        self.allow_web_access = bool(data.get("allow_web_access", False))
        self.web_access_mode = str(data.get("web_access_mode", "false"))
        self.locality = data.get("locality", {})

        changed = (
            self.ports != old_ports
            or self.allow_web_access != old_web
            or self.web_access_mode != old_mode
        )

        if changed:
            log.info(f"Config reloaded: ports={self.ports}, web_access={self.allow_web_access}, mode={self.web_access_mode}")

        return changed

    def check_for_changes(self) -> bool:
        """Poll the config file for changes. Returns True if changed."""
        if not self._config_path:
            return False
        return self._reload()

    def to_registration(self) -> dict:
        """Build the registration message for GhostMCP."""
        msg = {
            "type": "register",
            "client_id": self.client_id,
            "ports": self.ports,
            "allow_web_access": self.allow_web_access,
            "web_access_mode": self.web_access_mode,
        }
        if self.locality:
            msg["locality"] = self.locality
        return msg


# ---------------------------------------------------------------------------
# Bridge Client
# ---------------------------------------------------------------------------

class GhostBridge:
    """Local connectivity bridge for GhostMCP webapp testing and web access."""

    def __init__(self, config: BridgeConfig):
        self.config = config
        self.ws: Optional[websockets.WebSocketClientProtocol] = None
        self.running = False
        self._http_client: Optional[httpx.AsyncClient] = None

    async def start(self):
        """Connect to GhostMCP, register, and start handling requests."""
        self.running = True
        self._http_client = httpx.AsyncClient(timeout=30.0, follow_redirects=True)

        backoff = 5
        max_backoff = 30

        while self.running:
            try:
                log.info(f"Connecting to {self.config.server_url}...")
                async with websockets.connect(
                    self.config.server_url,
                    additional_headers={"X-Client-ID": self.config.client_id},
                    ping_interval=20,
                    ping_timeout=10,
                    close_timeout=5,
                ) as ws:
                    self.ws = ws
                    backoff = 5

                    # Register
                    await self._register(ws)

                    # Run message loop + config watcher concurrently
                    await asyncio.gather(
                        self._message_loop(ws),
                        self._config_watcher(ws),
                    )

            except websockets.ConnectionClosed as e:
                log.warning(f"Connection closed: {e}")
            except ConnectionRefusedError:
                log.warning(f"Connection refused — is GhostMCP running at {self.config.server_url}?")
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
        """Send registration message to GhostMCP."""
        msg = json.dumps(self.config.to_registration())
        await ws.send(msg)

        locality_str = ""
        if self.config.locality:
            locality_str = f", locality={self.config.locality.get('region', '?')}"

        log.info(
            f"Registered: ports={self.config.ports}, "
            f"web_access={self.config.allow_web_access}, "
            f"mode={self.config.web_access_mode}"
            f"{locality_str}"
        )

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

    async def _config_watcher(self, ws):
        """Poll config file for changes and re-register if needed."""
        while self.running:
            await asyncio.sleep(3)
            try:
                if self.config.check_for_changes():
                    log.info("Config changed — re-registering...")
                    await self._register(ws)
            except Exception as e:
                log.debug(f"Config watch error: {e}")

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
                asyncio.create_task(self._handle_request(ws, msg))
            elif msg_type == "heartbeat_ack":
                pass
            else:
                log.debug(f"Unknown message type: {msg_type}")

    async def _handle_request(self, ws, msg: dict):
        """Fetch a URL and return the response through the WebSocket."""
        req_id = msg.get("id", "unknown")
        method = msg.get("method", "GET").upper()
        url = msg.get("url", "")
        headers = msg.get("headers", {})
        body = msg.get("body")

        # Security check: is this a localhost request or a web request?
        from urllib.parse import urlparse
        parsed = urlparse(url)
        is_localhost = parsed.hostname in ("localhost", "127.0.0.1", "0.0.0.0")

        if not is_localhost and not self.config.allow_web_access:
            response = {
                "type": "error",
                "id": req_id,
                "error": "Web access not enabled. Set allow_web_access: true in config.",
            }
            await ws.send(json.dumps(response))
            log.warning(f"[{req_id}] Blocked web request (allow_web_access=false): {url}")
            return

        if is_localhost:
            port = parsed.port or 80
            if port not in self.config.ports:
                response = {
                    "type": "error",
                    "id": req_id,
                    "error": f"Port {port} not registered. Add it to your config.",
                }
                await ws.send(json.dumps(response))
                log.warning(f"[{req_id}] Blocked — port {port} not registered: {url}")
                return

        log.info(f"[{req_id}] {method} {url}{'  (web)' if not is_localhost else ''}")

        try:
            resp = await self._http_client.request(
                method=method,
                url=url,
                headers=headers,
                content=body.encode() if body else None,
            )

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


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="GhostMCP Local Connectivity Bridge — webapp testing + web access",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Config file (recommended — supports hot-reload):
  %(prog)s --config ~/.ghost_client.yaml

  # Quick CLI mode:
  %(prog)s --connect ws://10.0.10.7:8080/bridge --ports 8080,3000

  # CLI with web access:
  %(prog)s --connect ws://10.0.10.7:8080/bridge --ports 8080 --web-access
        """,
    )
    parser.add_argument(
        "--config", "-c",
        help="Path to YAML config file (default: ~/.ghost_client.yaml)",
    )
    parser.add_argument(
        "--connect",
        help="GhostMCP WebSocket URL (e.g. ws://10.0.10.7:8080/bridge)",
    )
    parser.add_argument(
        "--ports",
        help="Comma-separated localhost ports (e.g. 8080,3000)",
    )
    parser.add_argument(
        "--id", default="",
        help="Client identifier (default: auto-generated)",
    )
    parser.add_argument(
        "--web-access", action="store_true",
        help="Allow GhostMCP to route web requests through this machine",
    )
    parser.add_argument(
        "--proxy", action="store_true",
        help="Run as MCP stdio proxy (for opencode 'type: local' integration)",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true",
        help="Enable debug logging",
    )

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Determine config source
    if args.config:
        config = BridgeConfig.from_file(args.config)
    elif args.connect:
        ports = [int(p.strip()) for p in args.ports.split(",") if p.strip()] if args.ports else []
        config = BridgeConfig.from_cli(
            server=args.connect,
            ports=ports,
            client_id=args.id,
        )
        if args.web_access:
            config.allow_web_access = True
            config.web_access_mode = "self_only"
    else:
        # Try default config file location
        default_config = os.path.expanduser("~/.ghost_client.yaml")
        if os.path.exists(default_config):
            config = BridgeConfig.from_file(default_config)
        else:
            parser.error("No config file found. Use --config FILE or --connect URL --ports PORTS")
            return

    if not config.server_url:
        parser.error("No server URL specified. Set 'server' in config or use --connect")
        return

    # Dispatch to proxy mode or bridge-only mode
    if args.proxy:
        # MCP stdio proxy — opencode launches this as "type: local"
        if args.verbose:
            log.setLevel(logging.DEBUG)
        else:
            # In proxy mode, suppress bridge logs to stderr so they don't
            # interfere with JSON-RPC on stdout
            logging.getLogger("ghost_bridge").setLevel(logging.WARNING)
        main_proxy(config)
        return

    # Bridge-only mode — standalone, no stdio proxy
    bridge = GhostBridge(config)

    loop = asyncio.new_event_loop()

    # Signal handlers — not supported on Windows, use KeyboardInterrupt fallback
    try:
        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(sig, lambda: asyncio.ensure_future(bridge.shutdown()))
    except NotImplementedError:
        pass  # Windows — handled via KeyboardInterrupt below

    try:
        loop.run_until_complete(bridge.start())
    except KeyboardInterrupt:
        loop.run_until_complete(bridge.shutdown())
    finally:
        loop.close()


# ---------------------------------------------------------------------------
# MCP Stdio Proxy Mode
# ---------------------------------------------------------------------------
# When launched by opencode as a "type": "local" MCP server, this acts as
# a transparent proxy: reads JSON-RPC from stdin, forwards to GhostMCP via
# WebSocket, returns responses on stdout. Simultaneously handles bridge
# requests (localhost fetches) from the server.

class MCPProxy:
    """Stdio MCP proxy — forwards JSON-RPC between opencode and GhostMCP."""

    def __init__(self, config: BridgeConfig):
        self.config = config
        self.ws = None
        self.bridge = GhostBridge(config)
        self.running = False
        self._pending_responses: dict[str, asyncio.Future] = {}

    async def start(self):
        """Connect to GhostMCP and start proxying stdio ↔ WebSocket."""
        self.running = True

        # Connect WebSocket to GhostMCP
        backoff = 5
        while self.running:
            try:
                log.info(f"Connecting to {self.config.server_url}...")
                async with websockets.connect(
                    self.config.server_url.replace("/bridge", "/ws"),
                    additional_headers={"X-Client-ID": self.config.client_id},
                    ping_interval=20,
                    ping_timeout=10,
                    close_timeout=5,
                ) as mcp_ws:
                    self.ws = mcp_ws
                    backoff = 5

                    # Also connect bridge channel if ports/web_access configured
                    bridge_task = None
                    if self.config.ports or self.config.allow_web_access:
                        bridge_task = asyncio.create_task(self._run_bridge())

                    # Run stdin reader + ws reader concurrently
                    await asyncio.gather(
                        self._stdin_reader(mcp_ws),
                        self._ws_reader(mcp_ws),
                    )

            except websockets.ConnectionClosed as e:
                log.warning(f"MCP connection closed: {e}")
            except ConnectionRefusedError:
                log.warning(f"Connection refused: {self.config.server_url}")
            except Exception as e:
                log.error(f"Connection error: {type(e).__name__}: {e}")

            if not self.running:
                break

            log.info(f"Reconnecting in {backoff}s...")
            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, 30)

    async def _run_bridge(self):
        """Run the bridge connection in parallel with MCP proxy."""
        try:
            await self.bridge.start()
        except Exception as e:
            log.debug(f"Bridge task ended: {e}")

    async def _stdin_reader(self, ws):
        """Read JSON-RPC from stdin and forward to GhostMCP via WebSocket.
        
        Uses a thread for stdin reading to support Windows (ProactorEventLoop
        doesn't support connect_read_pipe on stdin).
        """
        loop = asyncio.get_event_loop()

        while self.running:
            try:
                # Read line from stdin in a thread (works on Windows + Unix)
                line_str = await loop.run_in_executor(None, sys.stdin.readline)
            except (EOFError, OSError):
                break

            if not line_str:
                break  # EOF

            line_str = line_str.strip()
            if not line_str:
                continue

            # Forward to GhostMCP
            try:
                await ws.send(line_str)
            except Exception as e:
                # Connection lost — write error response
                try:
                    msg = json.loads(line_str)
                    error_resp = json.dumps({
                        "jsonrpc": "2.0",
                        "id": msg.get("id"),
                        "error": {"code": -32000, "message": f"GhostMCP connection lost: {e}"}
                    })
                    sys.stdout.write(error_resp + "\n")
                    sys.stdout.flush()
                except Exception:
                    pass
                break

    async def _ws_reader(self, ws):
        """Read responses from GhostMCP WebSocket and write to stdout."""
        try:
            async for message in ws:
                if isinstance(message, bytes):
                    message = message.decode("utf-8")
                sys.stdout.write(message + "\n")
                sys.stdout.flush()
        except websockets.ConnectionClosed:
            pass

    async def shutdown(self):
        """Graceful shutdown."""
        self.running = False
        await self.bridge.shutdown()
        if self.ws:
            try:
                await self.ws.close()
            except Exception:
                pass


def main_proxy(config: BridgeConfig):
    """Run as MCP stdio proxy (launched by opencode/IDE)."""
    proxy = MCPProxy(config)

    loop = asyncio.new_event_loop()

    try:
        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(sig, lambda: asyncio.ensure_future(proxy.shutdown()))
    except NotImplementedError:
        pass

    try:
        loop.run_until_complete(proxy.start())
    except KeyboardInterrupt:
        loop.run_until_complete(proxy.shutdown())
    finally:
        loop.close()


if __name__ == "__main__":
    main()
