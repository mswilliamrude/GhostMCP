"""GhostMCP MCP tool interface — exposes OSINT tools via Model Context Protocol.

Implements the MCP JSON-RPC stdio protocol directly for Python 3.9 compatibility.
Uses fastmcp if available (Python 3.10+), otherwise runs a minimal stdio server.

Run with: python3 -m src.mcp (stdio mode)
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import sys
import time
from typing import Any, Callable, Optional
from urllib.parse import urlparse

import httpx


# ---------------------------------------------------------------------------
# Local Connectivity Bridge — client registry and fetch helper
# ---------------------------------------------------------------------------
# Bridge clients connect via WebSocket and register localhost ports they
# make available for testing. Optionally provide internet connectivity
# for GhostMCP in private VNets without egress.

_bridge_clients: dict[str, dict] = {}  # client_id -> {"ws", "ports", "web_access", "web_mode", "locality"}
_bridge_pending: dict[str, asyncio.Future] = {}  # request_id -> Future waiting for response
_shared_pool: list[str] = []  # client_ids with web_access_mode: shared
_pool_index: int = 0  # round-robin counter


def _should_use_bridge(url: str) -> bool:
    """Check if this URL should be routed through a local connectivity bridge."""
    parsed = urlparse(url)
    return parsed.hostname in ("localhost", "127.0.0.1", "0.0.0.0", "host.docker.internal")


def _should_use_web_bridge(url: str) -> bool:
    """Check if this URL should route through a bridge for internet access."""
    if not _bridge_clients:
        return False
    # If any bridge offers web access AND this is an external URL
    if _should_use_bridge(url):
        return False  # localhost goes through port-specific bridge
    return any(b.get("web_access") for b in _bridge_clients.values())


def _find_bridge_for_port(port: int) -> Optional[str]:
    """Find a bridge client that has the given port registered."""
    for client_id, info in _bridge_clients.items():
        if port in info.get("ports", []):
            return client_id
    return None


def _find_bridge_for_web(requesting_client: str = "") -> Optional[str]:
    """Find a bridge to route web requests through.
    
    Priority:
    1. Requesting client's own bridge (if self_only or shared)
    2. Round-robin from shared pool
    3. None (use direct connection)
    """
    global _pool_index

    # Check if the requesting client has their own bridge with web access
    if requesting_client and requesting_client in _bridge_clients:
        info = _bridge_clients[requesting_client]
        if info.get("web_access") and info.get("web_mode") in ("self_only", "shared"):
            return requesting_client

    # Round-robin from shared pool
    if _shared_pool:
        # Clean out disconnected bridges
        active = [c for c in _shared_pool if c in _bridge_clients]
        if active != _shared_pool:
            _shared_pool[:] = active

        if _shared_pool:
            _pool_index = _pool_index % len(_shared_pool)
            client_id = _shared_pool[_pool_index]
            _pool_index += 1
            return client_id

    return None


def _register_bridge(client_id: str, info: dict):
    """Register a bridge client and update the shared pool."""
    _bridge_clients[client_id] = info

    # Update shared pool
    if info.get("web_access") and info.get("web_mode") == "shared":
        if client_id not in _shared_pool:
            _shared_pool.append(client_id)
    else:
        if client_id in _shared_pool:
            _shared_pool.remove(client_id)


def _unregister_bridge(client_id: str):
    """Remove a bridge client and clean up."""
    _bridge_clients.pop(client_id, None)
    if client_id in _shared_pool:
        _shared_pool.remove(client_id)
    # Cancel pending requests
    for req_id, future in list(_bridge_pending.items()):
        if not future.done():
            future.set_result({"error": f"Bridge '{client_id}' disconnected"})


async def _detect_locality(ip: str) -> dict:
    """Auto-detect locality from a client's source IP via free GeoIP API.
    
    Returns dict with region, timezone, label — or empty dict on failure.
    Uses ip-api.com (free, no key, 45 req/min).
    """
    if ip in ("127.0.0.1", "::1", "localhost"):
        return {"region": "local", "timezone": "local", "label": "localhost"}
    
    # RFC 1918 / private ranges — can't geolocate
    if ip.startswith(("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                       "172.20.", "172.21.", "172.22.", "172.23.",
                       "172.24.", "172.25.", "172.26.", "172.27.",
                       "172.28.", "172.29.", "172.30.", "172.31.",
                       "192.168.")):
        return {"region": "private", "timezone": "unknown", "label": f"private ({ip})"}
    
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city,timezone,isp")
            if resp.status_code == 200:
                data = resp.json()
                if data.get("status") == "success":
                    region = data.get("regionName", "")
                    country = data.get("country", "")
                    city = data.get("city", "")
                    return {
                        "region": f"{country}-{region}",
                        "timezone": data.get("timezone", ""),
                        "label": f"{city}, {region}" if city else region,
                        "isp": data.get("isp", ""),
                        "auto_detected": True,
                    }
    except Exception:
        pass
    
    return {}


async def _fetch_via_bridge(url: str, method: str = "GET", headers: dict = None,
                            body: str = None, requesting_client: str = "") -> dict:
    """Route an HTTP request through a connected bridge client.
    
    Returns dict with 'status', 'headers', 'body' on success,
    or 'error' on failure. Includes 'bridge_client' and 'bridge_locality' for provenance.
    """
    parsed = urlparse(url)
    is_localhost = parsed.hostname in ("localhost", "127.0.0.1", "0.0.0.0", "host.docker.internal")

    if is_localhost:
        port = parsed.port or 80
        client_id = _find_bridge_for_port(port)
        if not client_id:
            return {"error": f"No bridge client has port {port} registered. "
                    f"Run: python3 ghost_bridge.py --connect ws://<ghostmcp>/bridge --ports {port}"}
    else:
        client_id = _find_bridge_for_web(requesting_client)
        if not client_id:
            return {"error": "No bridge with web access available. "
                    "Set allow_web_access: true in your bridge config."}

    bridge = _bridge_clients.get(client_id)
    if not bridge:
        return {"error": f"Bridge '{client_id}' not found"}

    ws = bridge.get("ws")
    if not ws:
        return {"error": f"Bridge '{client_id}' is disconnected"}

    import uuid
    req_id = str(uuid.uuid4())[:8]

    future = asyncio.get_event_loop().create_future()
    _bridge_pending[req_id] = future

    try:
        request_msg = json.dumps({
            "type": "request",
            "id": req_id,
            "method": method,
            "url": url,
            "headers": headers or {},
            "body": body,
        })
        await ws.send_text(request_msg)

        result = await asyncio.wait_for(future, timeout=30.0)

        # Tag with provenance
        result["bridge_client"] = client_id
        result["bridge_locality"] = bridge.get("locality", {}).get("region", "unknown")

        return result

    except asyncio.TimeoutError:
        return {"error": f"Bridge request timed out after 30s: {url}"}
    except Exception as e:
        return {"error": f"Bridge request failed: {e}"}
    finally:
        _bridge_pending.pop(req_id, None)

from .engines.base import SearchResult, SearchEngineError
from .engines.brave import BraveEngine
from .engines.brave_media import BraveMediaEngine, ImageResult, VideoResult, NewsResult
from .engines.bing import BingEngine
from .engines.duckduckgo import DuckDuckGoEngine
from .engines.google import GoogleEngine
from .engines.serper import SerperEngine
from .engines.searxng import SearXNGEngine
from .engines.rotator import EngineRotator
from .dorking.builder import build_dork, from_template
from .dorking.templates import get_template_names
from .proxy.manager import ProxyManager
from .proxy.fingerprint import get_headers
from .recon.certs import CertReport, inspect_cert, grade_cert, jarm_fingerprint
from .recon.hashes import HashLookup, detect_hash_type, HashReport
from .recon.render import render_page, RenderReport
from .recon.subdomains import enumerate_subdomains, dns_brute_force, SubdomainReport
from .recon.vulns import lookup_cve, search_cves, check_package, CVEResult, PackageVulnResult
from .recon.threats import threat_lookup, ThreatReport
from .recon.phone import PhoneReport, phone_lookup
from .recon.vehicles import VehicleReport, vehicle_lookup
from .recon.people import PeopleSearchResult, people_search
from .recon.email_intel import EmailReport, email_lookup
from .recon.username import UsernameReport, username_lookup
from .recon.court import CourtSearchResult, CourtCase, court_search
from .recon.breach import BreachSearchResult, BreachRecord, breach_search
from .recon.report import BackgroundReport, generate_report
from .recon.ip_intel import IPReport, ip_lookup
from .recon.dns_intel import DNSReport, dns_lookup
from .recon.asn import ASNReport, asn_lookup
from .recon.headers import HeadersReport, analyze_headers, grade_headers
from .recon.api_discovery import APIDiscoveryReport, api_discover
from .recon.gis import GISResult, GISError, gis_lookup, geocode_address
from .utils.config import ParanoiaLevel


# ---------------------------------------------------------------------------
# Engine Rotator Singleton — lazily initialized on first use
# ---------------------------------------------------------------------------

_rotator: Optional[EngineRotator] = None
_rotator_paranoia: Optional[str] = None


def _get_rotator(paranoia: str = "cautious") -> EngineRotator:
    """Get or create the module-level engine rotator singleton.

    The rotator persists across requests within the same process.
    Re-created if paranoia level changes (proxy config differs).
    """
    global _rotator, _rotator_paranoia

    if _rotator is not None and _rotator_paranoia == paranoia:
        return _rotator

    proxy = _get_proxy(paranoia)
    rotator = EngineRotator()

    # Register API engines (preferred — no CAPTCHA risk)
    serper = SerperEngine(proxy=proxy)
    if serper.available:
        rotator.register(
            serper,
            is_api=True,
            max_per_window=40,  # Conservative: 40 per 10 min (Serper: 2500/month ≈ ~83/day)
            base_cooldown=30.0,
        )

    brave = BraveEngine(proxy=proxy)
    if brave.available:
        rotator.register(
            brave,
            is_api=True,
            max_per_window=30,  # Conservative: 30 per 10 min (Brave: 2000/month ≈ ~67/day)
            base_cooldown=30.0,
        )

    bing = BingEngine(proxy=proxy)
    if bing.available:
        rotator.register(
            bing,
            is_api=True,
            max_per_window=20,  # Conservative: 20 per 10 min
            base_cooldown=30.0,
        )

    # SearXNG — self-hosted metasearch (API-based, no CAPTCHA)
    searxng = SearXNGEngine(proxy=proxy)
    if searxng.available:
        rotator.register(
            searxng,
            is_api=True,
            max_per_window=50,  # Self-hosted = generous limits
            base_cooldown=15.0,  # Quick recovery
        )

    # Register scraper engines (fallback — CAPTCHA risk)
    rotator.register(
        GoogleEngine(proxy=proxy, paranoia=paranoia),
        is_api=False,
        max_per_window=10,  # Google is aggressive about rate limiting
        base_cooldown=120.0,  # 2 min base cooldown for Google
    )

    rotator.register(
        DuckDuckGoEngine(proxy=proxy),
        is_api=False,
        max_per_window=15,  # DDG is less aggressive than Google
        base_cooldown=60.0,
    )

    _rotator = rotator
    _rotator_paranoia = paranoia
    return _rotator


# ---------------------------------------------------------------------------
# Minimal MCP stdio server (JSON-RPC 2.0 over stdin/stdout)
# ---------------------------------------------------------------------------

class MCPServer:
    """Minimal MCP server implementing JSON-RPC 2.0 over stdio.

    Registers tools with schemas and dispatches calls. Compatible with
    any MCP client (Claude Desktop, opencode, etc.).
    """

    def __init__(self, name: str, description: str = "") -> None:
        self.name = name
        self.description = description
        self._tools: dict[str, dict[str, Any]] = {}
        self._handlers: dict[str, Callable] = {}

    def tool(
        self,
        name: str,
        description: str,
        parameters: dict[str, Any],
    ) -> Callable:
        """Register a tool with its schema."""
        def decorator(fn: Callable) -> Callable:
            self._tools[name] = {
                "name": name,
                "description": description,
                "inputSchema": {
                    "type": "object",
                    "properties": parameters,
                },
            }
            self._handlers[name] = fn
            return fn
        return decorator

    async def handle_request(self, request: dict) -> dict:
        """Handle a single JSON-RPC request."""
        method = request.get("method", "")
        req_id = request.get("id")
        params = request.get("params", {})

        if method == "initialize":
            return self._response(req_id, {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {
                    "name": self.name,
                    "version": "0.1.0",
                },
            })

        if method == "notifications/initialized":
            return {}  # No response needed for notifications

        if method == "tools/list":
            tools_list = list(self._tools.values())
            return self._response(req_id, {"tools": tools_list})

        if method == "tools/call":
            tool_name = params.get("name", "")
            arguments = params.get("arguments", {})

            if tool_name not in self._handlers:
                return self._error(req_id, -32601, f"Tool not found: {tool_name}")

            try:
                handler = self._handlers[tool_name]
                result = await handler(**arguments)
                # Backward-compatible content handling:
                #  - If a tool returns a list of MCP content blocks (dicts with a
                #    "type" key, e.g. text/image), pass them through verbatim so
                #    tools can emit images (base64 PNG) alongside text.
                #  - Otherwise, wrap the stringified result in a text block
                #    (unchanged behavior for all existing str-returning tools).
                if isinstance(result, list) and all(
                    isinstance(b, dict) and "type" in b for b in result
                ):
                    content = result
                else:
                    content = [{"type": "text", "text": str(result)}]
                return self._response(req_id, {"content": content})
            except Exception as e:
                return self._response(req_id, {
                    "content": [{"type": "text", "text": f"Error: {e}"}],
                    "isError": True,
                })

        # Unknown method
        return self._error(req_id, -32601, f"Method not found: {method}")

    @staticmethod
    def _response(req_id: Any, result: Any) -> dict:
        return {"jsonrpc": "2.0", "id": req_id, "result": result}

    @staticmethod
    def _error(req_id: Any, code: int, message: str) -> dict:
        return {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}}

    async def run_stdio(self) -> None:
        """Run the MCP server over stdio (newline-delimited JSON-RPC)."""
        reader = asyncio.StreamReader()
        protocol = asyncio.StreamReaderProtocol(reader)
        await asyncio.get_event_loop().connect_read_pipe(lambda: protocol, sys.stdin)

        w_transport, w_protocol = await asyncio.get_event_loop().connect_write_pipe(
            asyncio.streams.FlowControlMixin, sys.stdout
        )
        writer = asyncio.StreamWriter(w_transport, w_protocol, reader, asyncio.get_event_loop())

        while True:
            line = await reader.readline()
            if not line:
                break

            line_str = line.decode("utf-8").strip()
            if not line_str:
                continue

            try:
                request = json.loads(line_str)
            except json.JSONDecodeError:
                continue

            response = await self.handle_request(request)
            if response:  # Notifications don't get responses
                writer.write((json.dumps(response) + "\n").encode("utf-8"))
                await writer.drain()


# ---------------------------------------------------------------------------
# Initialize MCP server
# ---------------------------------------------------------------------------

mcp = MCPServer("GhostMCP", description="Anonymous OSINT search and reconnaissance toolkit")


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def _get_proxy(paranoia: str) -> Optional[dict]:
    """Get proxy configuration for the given paranoia level."""
    mgr = ProxyManager()
    try:
        level = ParanoiaLevel(paranoia)
    except ValueError:
        level = ParanoiaLevel.CAUTIOUS
    return mgr.get_proxy(level)


def _format_results(results: list[SearchResult]) -> str:
    """Format search results as readable text."""
    if not results:
        return "No results found."

    lines: list[str] = []
    for i, r in enumerate(results, 1):
        lines.append(f"{i}. {r.title}")
        lines.append(f"   URL: {r.url}")
        if r.snippet:
            lines.append(f"   {r.snippet}")
        lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Tool implementations
# ---------------------------------------------------------------------------

@mcp.tool(
    name="ghost_search",
    description=(
        "Search the web anonymously using various search engines. "
        "Supports multiple engines with automatic fallback. Uses stealth "
        "techniques to avoid detection and rate limiting."
    ),
    parameters={
        "query": {"type": "string", "description": "Search query string."},
        "engine": {
            "type": "string",
            "description": (
                "Engine: auto, serper, brave, bing, google, duckduckgo, searxng, status. "
                "Auto uses intelligent round-robin rotation across available engines. "
                "Use 'status' to see engine health and rotation state."
            ),
            "default": "auto",
        },
        "paranoia": {
            "type": "string",
            "description": "OpSec level: casual, cautious, ghost, midnight.",
            "default": "cautious",
        },
        "num_results": {
            "type": "integer",
            "description": "Number of results (default 10, max 100).",
            "default": 10,
        },
    },
)
async def ghost_search(
    query: str,
    engine: str = "auto",
    paranoia: str = "cautious",
    num_results: int = 10,
) -> str:
    """Search the web anonymously using various search engines."""
    proxy = _get_proxy(paranoia)
    num_results = min(max(1, int(num_results)), 100)

    # Status mode — return rotator health info
    if engine == "status":
        rotator = _get_rotator(paranoia)
        status = rotator.get_status()
        if not status:
            return "No engines registered. Check API keys and configuration."
        lines = ["Engine Rotator Status", "=" * 40, ""]
        for name, info in status.items():
            avail = "AVAILABLE" if info["available"] else "UNAVAILABLE"
            engine_type = "API" if info["is_api"] else "Scraper"
            lines.append(f"[{name}] ({engine_type}) — {avail}")
            lines.append(f"  Window: {info['requests_in_window']}/{info['max_per_window']} requests")
            lines.append(f"  Lifetime: {info['successes']} ok / {info['failures']} fail / {info['total']} total")
            if info["consecutive_failures"] > 0:
                lines.append(f"  Consecutive failures: {info['consecutive_failures']}")
            if info["cooldown_remaining"] > 0:
                lines.append(f"  Cooldown: {info['cooldown_remaining']:.0f}s remaining")
            lines.append("")
        return "\n".join(lines)

    # Auto mode — use intelligent rotator
    if engine == "auto":
        rotator = _get_rotator(paranoia)
        results, engine_used = await rotator.search(query, num_results=num_results)
        if results:
            header = f"[{engine_used}] Results for: {query}\n\n"
            return header + _format_results(results)
        # All engines failed
        if engine_used:
            return f"All engines failed. Last error: {engine_used}"
        return "No results found across all engines."

    # Explicit engine — bypass rotation, use directly
    eng_map = {
        "serper": lambda: SerperEngine(proxy=proxy),
        "brave": lambda: BraveEngine(proxy=proxy),
        "bing": lambda: BingEngine(proxy=proxy),
        "google": lambda: GoogleEngine(proxy=proxy, paranoia=paranoia),
        "duckduckgo": lambda: DuckDuckGoEngine(proxy=proxy),
        "searxng": lambda: SearXNGEngine(proxy=proxy),
    }

    if engine not in eng_map:
        return f"Unknown engine '{engine}'. Available: auto, {', '.join(eng_map.keys())}, status"

    try:
        eng_instance = eng_map[engine]()
        results = await eng_instance.search(query, num_results=num_results)
        header = f"[{engine}] Results for: {query}\n\n"
        return header + _format_results(results)
    except SearchEngineError as e:
        return f"Engine error: {e}"


# ---------------------------------------------------------------------------
# Media search tool (images, videos, news via Brave)
# ---------------------------------------------------------------------------

def _format_image_results(results: list[ImageResult]) -> str:
    """Format image results as readable text."""
    if not results:
        return "No image results found."

    lines: list[str] = []
    for i, r in enumerate(results, 1):
        lines.append(f"{i}. {r.title}")
        lines.append(f"   Page: {r.url}")
        lines.append(f"   Image: {r.image_url}")
        if r.thumbnail_url:
            lines.append(f"   Thumb: {r.thumbnail_url}")
        if r.source:
            lines.append(f"   Source: {r.source}")
        if r.width and r.height:
            lines.append(f"   Size: {r.width}x{r.height}")
        lines.append("")

    return "\n".join(lines)


def _format_video_results(results: list[VideoResult]) -> str:
    """Format video results as readable text."""
    if not results:
        return "No video results found."

    lines: list[str] = []
    for i, r in enumerate(results, 1):
        lines.append(f"{i}. {r.title}")
        lines.append(f"   URL: {r.url}")
        if r.source:
            lines.append(f"   Source: {r.source}")
        if r.duration:
            lines.append(f"   Duration: {r.duration}")
        if r.published:
            lines.append(f"   Published: {r.published}")
        if r.description:
            lines.append(f"   {r.description[:200]}")
        if r.thumbnail_url:
            lines.append(f"   Thumb: {r.thumbnail_url}")
        lines.append("")

    return "\n".join(lines)


def _format_news_results(results: list[NewsResult]) -> str:
    """Format news results as readable text."""
    if not results:
        return "No news results found."

    lines: list[str] = []
    for i, r in enumerate(results, 1):
        lines.append(f"{i}. {r.title}")
        lines.append(f"   URL: {r.url}")
        if r.source:
            lines.append(f"   Source: {r.source}")
        if r.published:
            lines.append(f"   Published: {r.published}")
        if r.description:
            lines.append(f"   {r.description[:200]}")
        if r.thumbnail_url:
            lines.append(f"   Thumb: {r.thumbnail_url}")
        lines.append("")

    return "\n".join(lines)


@mcp.tool(
    name="ghost_media",
    description="Search for images, videos, or news via Brave Search API.",
    parameters={
        "query": {"type": "string", "description": "Search query."},
        "media_type": {
            "type": "string",
            "description": "Type: images, videos, or news.",
            "default": "images",
        },
        "num_results": {
            "type": "integer",
            "description": "Number of results (max 20).",
            "default": 10,
        },
    },
)
async def ghost_media(
    query: str,
    media_type: str = "images",
    num_results: int = 10,
) -> str:
    """Search for images, videos, or news via Brave Search API."""
    if not query:
        return "Error: query is required."

    media_type = media_type.strip().lower()
    if media_type not in ("images", "videos", "news"):
        return f"Error: unknown media_type '{media_type}'. Use: images, videos, or news."

    num_results = min(max(1, int(num_results)), 20)

    engine = BraveMediaEngine()

    if not engine.available:
        return (
            "Error: GHOST_BRAVE_KEY not set. "
            "Media search requires a Brave Search API key.\n"
            "Get a free key (2,000 searches/month) at https://brave.com/search/api/"
        )

    try:
        if media_type == "images":
            results = await engine.search_images(query, num_results=num_results)
            header = f"[brave/images] Results for: {query}\n\n"
            return header + _format_image_results(results)
        elif media_type == "videos":
            results = await engine.search_videos(query, num_results=num_results)
            header = f"[brave/videos] Results for: {query}\n\n"
            return header + _format_video_results(results)
        else:  # news
            results = await engine.search_news(query, num_results=num_results)
            header = f"[brave/news] Results for: {query}\n\n"
            return header + _format_news_results(results)
    except SearchEngineError as e:
        return f"Media search error: {e}"


# ---------------------------------------------------------------------------
# SearXNG metasearch tool — direct access with full parameter control
# ---------------------------------------------------------------------------

@mcp.tool(
    name="ghost_searxng",
    description=(
        "Search via SearXNG metasearch engine — aggregates results from Google, Bing, "
        "DuckDuckGo, Wikipedia, Reddit, GitHub, and 70+ other engines without tracking. "
        "Requires GHOST_SEARXNG_URL pointing to a SearXNG instance."
    ),
    parameters={
        "query": {"type": "string", "description": "Search query string."},
        "categories": {
            "type": "string",
            "description": (
                "Comma-separated categories: general, images, news, science, it, files, social media. "
                "Default: general."
            ),
            "default": "general",
        },
        "engines": {
            "type": "string",
            "description": (
                "Comma-separated engines to use (empty = all in category). "
                "Examples: google, bing, duckduckgo, wikipedia, reddit, github, arxiv, stackoverflow."
            ),
            "default": "",
        },
        "time_range": {
            "type": "string",
            "description": "Time filter: day, week, month, year. Empty = no filter.",
            "default": "",
        },
        "language": {
            "type": "string",
            "description": "Language code (e.g., 'en', 'de', 'fr'). Default: en.",
            "default": "en",
        },
        "num_results": {
            "type": "integer",
            "description": "Number of results (default 10, max 50).",
            "default": 10,
        },
    },
)
async def ghost_searxng(
    query: str,
    categories: str = "general",
    engines: str = "",
    time_range: str = "",
    language: str = "en",
    num_results: int = 10,
) -> str:
    """Search via SearXNG metasearch engine with full parameter control."""
    if not query:
        return "Error: query is required."

    num_results = min(max(1, int(num_results)), 50)

    engine = SearXNGEngine()

    if not engine.available:
        return (
            "Error: GHOST_SEARXNG_URL not set. "
            "Point it to a SearXNG instance:\n"
            "  1. Self-host: docker run -p 8888:8080 searxng/searxng\n"
            "  2. Or use a public instance from https://searx.space/\n"
            "  3. Export: export GHOST_SEARXNG_URL='http://localhost:8888'"
        )

    try:
        results = await engine.search(
            query=query,
            num_results=num_results,
            categories=categories,
            engines=engines,
            language=language,
            time_range=time_range,
        )

        if not results:
            return f"No results found for: {query}"

        # Format results
        lines = [f"[searxng] Results for: {query}", ""]

        if categories != "general":
            lines.append(f"Categories: {categories}")
        if engines:
            lines.append(f"Engines: {engines}")
        if time_range:
            lines.append(f"Time range: {time_range}")
        if categories != "general" or engines or time_range:
            lines.append("")

        for i, r in enumerate(results, 1):
            lines.append(f"{i}. {r.title}")
            lines.append(f"   URL: {r.url}")
            if r.snippet:
                lines.append(f"   {r.snippet[:300]}")
            # Show which engine provided this result
            if ":" in r.source_engine:
                _, src = r.source_engine.split(":", 1)
                lines.append(f"   Source: {src}")
            lines.append("")

        return "\n".join(lines)

    except SearchEngineError as e:
        return f"SearXNG error: {e}"


@mcp.tool(
    name="ghost_perplexity",
    description=(
        "Query Perplexity AI for search-augmented answers with citations. "
        "Perplexity combines web search with LLM synthesis to provide "
        "grounded, cited answers. Best for research questions, technical "
        "lookups, current events, and anything needing up-to-date sources. "
        "Requires GHOST_PERPLEXITY_KEY environment variable."
    ),
    parameters={
        "query": {
            "type": "string",
            "description": "The research question or search query.",
        },
        "model": {
            "type": "string",
            "description": (
                "Perplexity model: sonar (fast, cheap), sonar-pro (better, "
                "more sources), sonar-deep-research (thorough, slow). Default: sonar-pro."
            ),
            "default": "sonar-pro",
        },
        "search_recency": {
            "type": "string",
            "description": (
                "Filter results by time: month, week, day, hour. "
                "Empty string = no time filter."
            ),
            "default": "",
        },
    },
)
async def ghost_perplexity(
    query: str,
    model: str = "sonar-pro",
    search_recency: str = "",
) -> str:
    """Query Perplexity for search-augmented answers with citations."""
    if not query:
        return "Error: query is required."

    api_key = os.environ.get("GHOST_PERPLEXITY_KEY", "")
    if not api_key:
        return (
            "Error: GHOST_PERPLEXITY_KEY not set.\n"
            "Get an API key at: https://www.perplexity.ai/settings/api\n"
            "Then set: export GHOST_PERPLEXITY_KEY=pplx-..."
        )

    valid_models = {"sonar", "sonar-pro", "sonar-deep-research"}
    if model not in valid_models:
        return f"Error: unknown model '{model}'. Use: {', '.join(sorted(valid_models))}"

    url = "https://api.perplexity.ai/chat/completions"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }

    messages = [
        {
            "role": "system",
            "content": (
                "You are a research assistant. Provide detailed, accurate answers "
                "with specific citations. Include URLs for sources when available."
            ),
        },
        {"role": "user", "content": query},
    ]

    payload: dict[str, Any] = {
        "model": model,
        "messages": messages,
    }

    if search_recency:
        valid_recency = {"month", "week", "day", "hour"}
        if search_recency in valid_recency:
            payload["search_recency_filter"] = search_recency

    try:
        async with httpx.AsyncClient(timeout=120.0) as client:
            resp = await client.post(url, headers=headers, json=payload)

            if resp.status_code == 401:
                return "Error: Invalid GHOST_PERPLEXITY_KEY (401 Unauthorized)."
            if resp.status_code == 429:
                return "Error: Perplexity rate limit exceeded. Try again later."
            if resp.status_code != 200:
                return f"Error: Perplexity API returned {resp.status_code}: {resp.text[:200]}"

            data = resp.json()

        # Extract the answer
        choices = data.get("choices", [])
        if not choices:
            return "Error: No response from Perplexity."

        answer = choices[0].get("message", {}).get("content", "")
        if not answer:
            return "Error: Empty response from Perplexity."

        # Extract citations if present
        citations = data.get("citations", [])

        # Build formatted output
        lines = [f"[perplexity/{model}] Research: {query}", ""]
        lines.append(answer)

        if citations:
            lines.append("")
            lines.append("--- Sources ---")
            for i, cite in enumerate(citations, 1):
                if isinstance(cite, str):
                    lines.append(f"  [{i}] {cite}")
                elif isinstance(cite, dict):
                    lines.append(f"  [{i}] {cite.get('url', cite.get('title', str(cite)))}")

        # Token usage info
        usage = data.get("usage", {})
        if usage:
            lines.append("")
            lines.append(
                f"Tokens: {usage.get('prompt_tokens', '?')} in / "
                f"{usage.get('completion_tokens', '?')} out"
            )

        return "\n".join(lines)

    except httpx.TimeoutException:
        return f"Error: Perplexity request timed out (model={model}, query may be too complex)."
    except httpx.ConnectError as e:
        return f"Error: Cannot connect to Perplexity API: {e}"
    except Exception as e:
        return f"Error: Perplexity query failed: {type(e).__name__}: {e}"


@mcp.tool(
    name="ghost_dork",
    description=(
        "Build and optionally execute a Google dork query. Use predefined templates "
        "or combine operators (site, filetype, inurl, intitle, intext, exclude)."
    ),
    parameters={
        "query": {"type": "string", "description": "Base search terms.", "default": ""},
        "template": {
            "type": "string",
            "description": (
                "Template name: exposed_configs, login_pages, directory_listing, "
                "git_exposed, env_files, api_docs, error_messages, tech_stack, "
                "database_dumps, sensitive_docs, subdomains, backup_files."
            ),
        },
        "domain": {"type": "string", "description": "Target domain (site: operator)."},
        "filetype": {"type": "string", "description": "File extension to search for."},
        "inurl": {"type": "string", "description": "String that must appear in URL."},
        "intitle": {"type": "string", "description": "String that must appear in title."},
        "intext": {"type": "string", "description": "String that must appear in body."},
        "exclude": {"type": "string", "description": "Comma-separated terms to exclude."},
        "execute": {"type": "boolean", "description": "Run the search (default true).", "default": True},
        "engine": {"type": "string", "description": "Engine for execution.", "default": "auto"},
        "paranoia": {"type": "string", "description": "OpSec level.", "default": "cautious"},
        "num_results": {"type": "integer", "description": "Results count.", "default": 10},
    },
)
async def ghost_dork(
    query: str = "",
    template: Optional[str] = None,
    domain: Optional[str] = None,
    filetype: Optional[str] = None,
    inurl: Optional[str] = None,
    intitle: Optional[str] = None,
    intext: Optional[str] = None,
    exclude: Optional[str] = None,
    execute: bool = True,
    engine: str = "auto",
    paranoia: str = "cautious",
    num_results: int = 10,
) -> str:
    """Build and optionally execute a Google dork query."""
    if template:
        try:
            kwargs = {}
            if domain:
                kwargs["domain"] = domain
            dork_query = from_template(template, **kwargs)
        except ValueError as e:
            return f"Template error: {e}"
    else:
        if not query and not domain:
            templates = get_template_names()
            return (
                "Provide a query or use a template.\n\n"
                f"Available templates: {', '.join(templates)}\n\n"
                "Example: ghost_dork(template='exposed_configs', domain='example.com')"
            )

        exclude_list = [e.strip() for e in exclude.split(",")] if exclude else None
        dork_query = build_dork(
            query=query,
            site=domain,
            filetype=filetype,
            inurl=inurl,
            intitle=intitle,
            intext=intext,
            exclude=exclude_list,
        )

    output = f"Dork: {dork_query}\n"

    if not execute:
        return output

    output += "\n"
    result = await ghost_search(
        query=dork_query,
        engine=engine,
        paranoia=paranoia,
        num_results=int(num_results),
    )
    return output + result


@mcp.tool(
    name="ghost_fetch",
    description=(
        "Fetch a URL and extract its content. Supports text extraction, "
        "raw HTML, response headers, and link extraction."
    ),
    parameters={
        "url": {"type": "string", "description": "The URL to fetch."},
        "extract": {
            "type": "string",
            "description": "Mode: text (readable), html (raw), headers, links.",
            "default": "text",
        },
        "paranoia": {"type": "string", "description": "OpSec level.", "default": "cautious"},
    },
)
async def ghost_fetch(
    url: str,
    extract: str = "text",
    paranoia: str = "cautious",
) -> str:
    """Fetch a URL and extract its content."""
    
    # Check if this should route through a local connectivity bridge
    if _should_use_bridge(url):
        bridge_resp = await _fetch_via_bridge(url)
        if "error" in bridge_resp:
            return f"Bridge error: {bridge_resp['error']}"
        
        # Use the bridge response as if we fetched directly
        status = bridge_resp.get("status", 0)
        resp_text = bridge_resp.get("body", "")
        resp_headers = bridge_resp.get("headers", {})
        
        if status >= 400:
            return f"HTTP Error: {status} for {url}"
        
        if extract == "html":
            if len(resp_text) > 50000:
                return resp_text[:50000] + "\n\n[... truncated at 50KB ...]"
            return resp_text
        
        if extract == "headers":
            lines = [f"{k}: {v}" for k, v in resp_headers.items()]
            return "\n".join(lines)
        
        if extract == "links":
            links = re.findall(r'href="(https?://[^"]+)"', resp_text)
            unique_links = sorted(set(links))
            if not unique_links:
                return "No links found on page."
            return "\n".join(unique_links)
        
        # Default: text extraction
        text = re.sub(r"<script[^>]*>.*?</script>", "", resp_text, flags=re.DOTALL)
        text = re.sub(r"<style[^>]*>.*?</style>", "", text, flags=re.DOTALL)
        text = re.sub(r"<[^>]+>", " ", text)
        text = re.sub(r"\s+", " ", text).strip()
        if len(text) > 20000:
            text = text[:20000] + "\n\n[... truncated at 20KB ...]"
        return f"Content from {url} (via bridge):\n\n{text}"
    
    # Direct fetch (no bridge needed)
    proxy = _get_proxy(paranoia)
    headers = get_headers(paranoia)

    transport = None
    if proxy:
        transport = httpx.AsyncHTTPTransport(proxy=proxy.get("all"))

    try:
        async with httpx.AsyncClient(
            transport=transport,
            timeout=30.0,
            follow_redirects=True,
        ) as client:
            resp = await client.get(url, headers=headers)
            resp.raise_for_status()
    except httpx.HTTPStatusError as e:
        return f"HTTP Error: {e.response.status_code} for {url}"
    except httpx.RequestError as e:
        return f"Request failed: {e}"

    if extract == "html":
        html = resp.text
        if len(html) > 50000:
            return html[:50000] + "\n\n[... truncated at 50KB ...]"
        return html

    if extract == "headers":
        lines = [f"{k}: {v}" for k, v in resp.headers.items()]
        return "\n".join(lines)

    if extract == "links":
        links = re.findall(r'href="(https?://[^"]+)"', resp.text)
        unique_links = sorted(set(links))
        if not unique_links:
            return "No links found on page."
        return "\n".join(unique_links)

    # Default: text extraction
    text = re.sub(r"<script[^>]*>.*?</script>", "", resp.text, flags=re.DOTALL)
    text = re.sub(r"<style[^>]*>.*?</style>", "", text, flags=re.DOTALL)
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"\s+", " ", text).strip()

    if len(text) > 20000:
        text = text[:20000] + "\n\n[... truncated at 20KB ...]"

    return f"Content from {url}:\n\n{text}"


@mcp.tool(
    name="ghost_recon",
    description=(
        "Reconnaissance on a target domain. Runs dorking-based modules: "
        "subdomains, configs, tech. Placeholder for future expansion."
    ),
    parameters={
        "domain": {"type": "string", "description": "Target domain to investigate."},
        "modules": {
            "type": "array",
            "items": {"type": "string"},
            "description": "Modules to run: subdomains, configs, tech. Default: [subdomains].",
        },
    },
)
async def ghost_recon(
    domain: str,
    modules: Optional[list] = None,
) -> str:
    """Reconnaissance on a target domain."""
    if modules is None:
        modules = ["subdomains"]

    output_parts: list[str] = [f"Recon target: {domain}\n{'=' * 40}\n"]

    for module in modules:
        if module == "subdomains":
            output_parts.append("\n[Subdomains] Searching for subdomains...\n")
            result = await ghost_dork(
                template="subdomains",
                domain=domain,
                execute=True,
                num_results=20,
            )
            output_parts.append(result)

        elif module == "configs":
            output_parts.append("\n[Configs] Searching for exposed configs...\n")
            result = await ghost_dork(
                template="exposed_configs",
                domain=domain,
                execute=True,
                num_results=10,
            )
            output_parts.append(result)

        elif module == "tech":
            output_parts.append("\n[Tech Stack] Identifying technologies...\n")
            result = await ghost_dork(
                template="tech_stack",
                domain=domain,
                execute=True,
                num_results=10,
            )
            output_parts.append(result)

        else:
            output_parts.append(
                f"\n[{module}] Module not yet implemented. "
                f"Available: subdomains, configs, tech\n"
            )

    return "\n".join(output_parts)


# ---------------------------------------------------------------------------
# Hash intelligence tool
# ---------------------------------------------------------------------------

def _format_hash_report(report: HashReport) -> str:
    """Format a HashReport into readable text."""
    lines: list[str] = []
    lines.append(f"Hash: {report.hash_value}")
    lines.append(f"Type: {report.hash_type}")
    lines.append(f"Verdict: {report.verdict.upper()}")
    lines.append("")

    # CIRCL
    if report.circl is not None:
        if report.circl.get("known"):
            lines.append(f"[CIRCL] Known: {report.circl['filename']} (source: {report.circl['source']})")
        else:
            lines.append("[CIRCL] Not found in NSRL database")
    elif "circl" in report.errors:
        lines.append(f"[CIRCL] Error: {report.errors['circl']}")

    # MalwareBazaar
    if report.malwarebazaar is not None:
        mb = report.malwarebazaar
        lines.append(f"[MalwareBazaar] Family: {mb['family']}, Type: {mb['file_type']}")
        if mb["tags"]:
            lines.append(f"  Tags: {', '.join(mb['tags'])}")
        if mb["first_seen"]:
            lines.append(f"  First seen: {mb['first_seen']}")
    elif "malwarebazaar" in report.errors:
        lines.append(f"[MalwareBazaar] Error: {report.errors['malwarebazaar']}")

    # ThreatFox
    if report.threatfox is not None:
        tf = report.threatfox
        lines.append(f"[ThreatFox] Malware: {tf['malware']}")
        if tf["c2"]:
            lines.append(f"  C2 servers: {', '.join(tf['c2'])}")
        if tf["campaign"]:
            lines.append(f"  Campaign: {tf['campaign']}")
    elif "threatfox" in report.errors:
        lines.append(f"[ThreatFox] Error: {report.errors['threatfox']}")

    # VirusTotal
    if report.virustotal is not None:
        vt = report.virustotal
        lines.append(f"[VirusTotal] Detections: {vt['detections']}/{vt['total']}")
        if vt.get("name"):
            lines.append(f"  Name: {vt['name']}")
    elif "virustotal" in report.errors:
        lines.append(f"[VirusTotal] Error: {report.errors['virustotal']}")

    return "\n".join(lines)


@mcp.tool(
    name="ghost_hash",
    description=(
        "Look up a hash (MD5, SHA1, SHA256, SHA512) against threat intelligence "
        "services (CIRCL, MalwareBazaar, ThreatFox, VirusTotal). Can also compute "
        "hashes from a local file path."
    ),
    parameters={
        "hash_value": {
            "type": "string",
            "description": "The hash to look up (hex string).",
        },
        "file_path": {
            "type": "string",
            "description": "Compute hash from file instead of direct lookup.",
        },
    },
)
async def ghost_hash(
    hash_value: Optional[str] = None,
    file_path: Optional[str] = None,
) -> str:
    """Look up a hash against threat intelligence services."""
    if not hash_value and not file_path:
        return "Error: Provide either hash_value or file_path."

    lookup = HashLookup()

    try:
        if file_path:
            report = await lookup.lookup_file(file_path)
        else:
            report = await lookup.lookup(hash_value)
    except (ValueError, FileNotFoundError) as e:
        return f"Error: {e}"

    return _format_hash_report(report)


# ---------------------------------------------------------------------------
# Subdomain enumeration tool
# ---------------------------------------------------------------------------

def _format_subdomain_report(report: SubdomainReport) -> str:
    """Format a SubdomainReport into readable text."""
    if report.error:
        return f"Error enumerating subdomains for {report.domain}: {report.error}"

    lines: list[str] = []
    lines.append(f"Subdomain enumeration: {report.domain}")
    lines.append(f"Total certificates found: {report.total_certs}")
    lines.append(f"Unique subdomains: {len(report.subdomains)}")
    lines.append("")

    if not report.subdomains:
        lines.append("No subdomains found.")
        return "\n".join(lines)

    for sub in report.subdomains:
        lines.append(f"  {sub}")

    return "\n".join(lines)


@mcp.tool(
    name="ghost_subdomains",
    description=(
        "Enumerate subdomains for a domain using Certificate Transparency logs (crt.sh), "
        "DNS brute force, or both. Returns deduplicated, sorted list of subdomains."
    ),
    parameters={
        "domain": {
            "type": "string",
            "description": "Target domain to enumerate subdomains for (e.g. example.com).",
        },
        "include_expired": {
            "type": "boolean",
            "description": "Include certs past their not_after date (default false).",
            "default": False,
        },
        "method": {
            "type": "string",
            "description": "Enumeration method: crt (crt.sh CT logs), dns (DNS brute force), all (both merged).",
            "default": "crt",
        },
    },
)
async def ghost_subdomains(
    domain: str,
    include_expired: bool = False,
    method: str = "crt",
) -> str:
    """Enumerate subdomains via Certificate Transparency logs and/or DNS brute force."""
    if not domain:
        return "Error: domain is required."

    method = method.strip().lower()
    if method not in ("crt", "dns", "all"):
        return f"Error: unknown method '{method}'. Use crt, dns, or all."

    if method == "crt":
        report = await enumerate_subdomains(domain, include_expired=include_expired)
        return _format_subdomain_report(report)

    if method == "dns":
        found = await dns_brute_force(domain)
        if not found:
            return f"No subdomains found via DNS brute force for {domain}."
        lines = [f"DNS brute force: {domain}", f"Subdomains found: {len(found)}", ""]
        for sub in found:
            lines.append(f"  {sub}")
        return "\n".join(lines)

    if method == "all":
        # Run both in parallel, merge and deduplicate
        crt_report, dns_found = await asyncio.gather(
            enumerate_subdomains(domain, include_expired=include_expired),
            dns_brute_force(domain),
        )
        all_subs = sorted(set(crt_report.subdomains) | set(dns_found))
        lines = [
            f"Subdomain enumeration (all methods): {domain}",
            f"  crt.sh: {len(crt_report.subdomains)} found ({crt_report.total_certs} certs)",
            f"  DNS brute: {len(dns_found)} found",
            f"  Combined unique: {len(all_subs)}",
            "",
        ]
        for sub in all_subs:
            source = []
            if sub in crt_report.subdomains:
                source.append("crt")
            if sub in dns_found:
                source.append("dns")
            lines.append(f"  {sub}  [{','.join(source)}]")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Vulnerability intelligence tools
# ---------------------------------------------------------------------------

def _format_cve_result(cve: CVEResult) -> str:
    """Format a CVEResult into readable text."""
    lines: list[str] = []
    lines.append(f"{cve.cve_id} [{cve.severity}]")
    if cve.cvss_score is not None:
        lines.append(f"  CVSS: {cve.cvss_score}")
    lines.append(f"  Published: {cve.published}")
    lines.append(f"  {cve.description[:300]}")

    if cve.epss_score is not None:
        lines.append(f"  EPSS: {cve.epss_score:.4f} (percentile: {cve.epss_percentile:.4f})")
    if cve.in_kev:
        lines.append("  ** CISA KEV: Known Exploited Vulnerability **")

    if cve.affected_products:
        lines.append(f"  Affected: {', '.join(cve.affected_products[:5])}")
    if cve.references:
        lines.append(f"  Refs: {', '.join(cve.references[:3])}")

    return "\n".join(lines)


@mcp.tool(
    name="ghost_cve",
    description=(
        "Look up a specific CVE by ID or search for CVEs by keyword. "
        "Returns severity, CVSS score, EPSS exploit probability, and "
        "CISA KEV status."
    ),
    parameters={
        "cve_id": {
            "type": "string",
            "description": "Specific CVE ID to look up (e.g. CVE-2024-1234).",
        },
        "keyword": {
            "type": "string",
            "description": "Search keyword for CVE lookup.",
        },
        "max_results": {
            "type": "integer",
            "description": "Maximum results for keyword search (default 5).",
            "default": 5,
        },
    },
)
async def ghost_cve(
    cve_id: Optional[str] = None,
    keyword: Optional[str] = None,
    max_results: int = 5,
) -> str:
    """Look up a specific CVE or search by keyword."""
    if not cve_id and not keyword:
        return "Error: Provide either cve_id or keyword."

    if cve_id:
        result = await lookup_cve(cve_id)
        if result is None:
            return f"CVE not found: {cve_id}"
        return _format_cve_result(result)

    # Keyword search
    results = await search_cves(keyword, max_results=int(max_results))
    if not results:
        return f"No CVEs found for: {keyword}"

    lines = [f"CVE search: {keyword} ({len(results)} results)\n"]
    for cve in results:
        lines.append(_format_cve_result(cve))
        lines.append("")
    return "\n".join(lines)


@mcp.tool(
    name="ghost_vuln",
    description=(
        "Check a package for known vulnerabilities via OSV.dev. "
        "Supports PyPI, npm, Go, crates.io, and other ecosystems."
    ),
    parameters={
        "package": {
            "type": "string",
            "description": "Package name to check (e.g. requests, lodash).",
        },
        "ecosystem": {
            "type": "string",
            "description": "Package ecosystem: PyPI, npm, Go, crates.io, etc.",
            "default": "PyPI",
        },
    },
)
async def ghost_vuln(
    package: str,
    ecosystem: str = "PyPI",
) -> str:
    """Check a package for known vulnerabilities."""
    if not package:
        return "Error: package is required."

    result = await check_package(package, ecosystem=ecosystem)

    if not result.vulnerabilities:
        return f"No known vulnerabilities for {ecosystem}/{package}."

    lines = [f"Vulnerabilities for {ecosystem}/{package}: {len(result.vulnerabilities)} found\n"]
    for vuln in result.vulnerabilities:
        lines.append(_format_cve_result(vuln))
        lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Threat intelligence tool
# ---------------------------------------------------------------------------

def _format_threat_report(report: ThreatReport) -> str:
    """Format a ThreatReport into readable text."""
    lines: list[str] = []
    lines.append(f"Threat lookup: {report.query}")
    lines.append(f"Sources queried: {', '.join(report.sources_queried)}")
    lines.append(f"Total indicators: {len(report.entries)}")
    lines.append("")

    if report.errors:
        for src, err in report.errors.items():
            lines.append(f"  [{src}] Error: {err}")
        lines.append("")

    for entry in report.entries:
        lines.append(f"[{entry.source}] {entry.indicator}")
        lines.append(f"  Type: {entry.indicator_type} | Threat: {entry.threat_type}")
        if entry.malware_family:
            lines.append(f"  Malware: {entry.malware_family}")
        if entry.tags:
            lines.append(f"  Tags: {', '.join(entry.tags)}")
        if entry.first_seen:
            lines.append(f"  First seen: {entry.first_seen}")
        if entry.reference:
            lines.append(f"  Ref: {entry.reference}")
        lines.append("")

    return "\n".join(lines)


@mcp.tool(
    name="ghost_threat",
    description=(
        "Look up an indicator (URL, IP, domain, hash) across threat intelligence "
        "feeds including URLhaus, ThreatFox, RansomWatch, and Feodo Tracker."
    ),
    parameters={
        "query": {
            "type": "string",
            "description": "Indicator to look up (URL, IP, domain, or hash).",
        },
        "sources": {
            "type": "string",
            "description": "Comma-separated sources: urlhaus,threatfox,ransomwatch,feodo. Default: all.",
        },
        "days": {
            "type": "integer",
            "description": "Days of recent IOCs for ThreatFox (default 7).",
            "default": 7,
        },
    },
)
async def ghost_threat(
    query: str,
    sources: Optional[str] = None,
    days: int = 7,
) -> str:
    """Look up an indicator across threat intelligence feeds."""
    if not query:
        return "Error: query is required."

    source_list = None
    if sources:
        source_list = [s.strip() for s in sources.split(",")]

    report = await threat_lookup(query, sources=source_list, days=int(days))
    return _format_threat_report(report)

    if method == "dns":
        found = await dns_brute_force(domain)
        lines: list[str] = []
        lines.append(f"DNS brute force: {domain}")
        lines.append(f"Subdomains found: {len(found)}")
        lines.append("")
        if not found:
            lines.append("No subdomains resolved.")
        else:
            for sub in found:
                lines.append(f"  {sub}")
        return "\n".join(lines)

    # method == "all" — run both, merge and deduplicate
    crt_report, dns_found = await asyncio.gather(
        enumerate_subdomains(domain, include_expired=include_expired),
        dns_brute_force(domain),
    )
    merged: set[str] = set(crt_report.subdomains) | set(dns_found)
    all_sorted = sorted(merged)

    lines = []
    lines.append(f"Subdomain enumeration (all methods): {domain}")
    if crt_report.error:
        lines.append(f"crt.sh error: {crt_report.error}")
    else:
        lines.append(f"crt.sh certificates found: {crt_report.total_certs}")
    lines.append(f"DNS brute force resolved: {len(dns_found)}")
    lines.append(f"Unique subdomains (merged): {len(all_sorted)}")
    lines.append("")
    if not all_sorted:
        lines.append("No subdomains found.")
    else:
        for sub in all_sorted:
            lines.append(f"  {sub}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# TLS certificate inspection tool
# ---------------------------------------------------------------------------

def _format_cert_report(report: CertReport) -> str:
    """Format a CertReport into readable text."""
    if report.error:
        return f"Error inspecting {report.host}:{report.port}: {report.error}"

    lines: list[str] = []

    # Grade prominently at the top
    if report.grade:
        grade_line = f"Grade: {report.grade} ({report.score}/100)"
        lines.append(grade_line)
        lines.append("")

    lines.append(f"TLS Certificate: {report.host}:{report.port}")
    lines.append("=" * 50)
    lines.append(f"Subject:     {report.subject}")
    lines.append(f"Issuer:      {report.issuer}")
    lines.append(f"Not Before:  {report.not_before}")
    lines.append(f"Not After:   {report.not_after}")
    lines.append(f"Expiry:      {report.days_until_expiry} days")
    if report.is_expired:
        lines.append("  ** CERTIFICATE IS EXPIRED **")
    if report.is_self_signed:
        lines.append("  ** SELF-SIGNED CERTIFICATE **")
    lines.append("")
    lines.append(f"Serial:      {report.serial}")
    lines.append(f"SHA-256:     {report.fingerprint_sha256}")
    lines.append(f"Protocol:    {report.protocol}")
    lines.append(f"Cipher:      {report.cipher}")
    lines.append(f"Key Type:    {report.key_type}")
    lines.append("")

    if report.sans:
        lines.append(f"SANs ({len(report.sans)}):")
        for san in report.sans:
            lines.append(f"  {san}")
        lines.append("")

    if report.chain:
        lines.append(f"Chain ({len(report.chain)}):")
        for i, cn in enumerate(report.chain):
            lines.append(f"  [{i}] {cn}")
        lines.append("")

    # Grade details breakdown
    if report.grade_details:
        lines.append("Score Breakdown:")
        lines.append(f"  Protocol:       {report.grade_details.get('protocol', 0)}/30")
        lines.append(f"  Key Strength:   {report.grade_details.get('key_strength', 0)}/20")
        lines.append(f"  Validity:       {report.grade_details.get('validity', 0)}/20")
        lines.append(f"  Cipher:         {report.grade_details.get('cipher', 0)}/15")
        lines.append(f"  Chain:          {report.grade_details.get('chain', 0)}/15")
        lines.append("")

    # Warnings
    if report.warnings:
        lines.append(f"Warnings ({len(report.warnings)}):")
        for w in report.warnings:
            lines.append(f"  ! {w}")
        lines.append("")

    # JARM fingerprint (if computed)
    if report.jarm_hash:
        lines.append(f"JARM Hash:   {report.jarm_hash}")

    return "\n".join(lines)


@mcp.tool(
    name="ghost_cert",
    description=(
        "Inspect the TLS certificate of a host. Connects to host:port, pulls the "
        "certificate, and reports subject, issuer, expiry, SANs, fingerprint, "
        "protocol, cipher suite, key type, chain, and self-signed/expired status. "
        "Grades the certificate A+ through F based on protocol, key strength, "
        "validity, cipher, and chain completeness."
    ),
    parameters={
        "host": {
            "type": "string",
            "description": "Target hostname to inspect (e.g. example.com).",
        },
        "port": {
            "type": "integer",
            "description": "TLS port (default 443).",
            "default": 443,
        },
        "include_jarm": {
            "type": "boolean",
            "description": "Compute JARM TLS fingerprint (slower, ~10-40s extra).",
            "default": False,
        },
    },
)
async def ghost_cert(
    host: str,
    port: int = 443,
    include_jarm: bool = False,
) -> str:
    """Inspect the TLS certificate of a host."""
    if not host:
        return "Error: host is required."

    report = await inspect_cert(host, port=port)

    # Optionally compute JARM fingerprint
    if include_jarm and not report.error:
        jarm_hash = await jarm_fingerprint(host, port=port)
        report.jarm_hash = jarm_hash

    return _format_cert_report(report)


# ---------------------------------------------------------------------------
# Headless browser rendering tool
# ---------------------------------------------------------------------------

@mcp.tool(
    name="ghost_render",
    description=(
        "Render a web page using headless Chromium browser. Captures the rendered DOM "
        "(after JavaScript execution), console.log/error output, and uncaught JS errors. "
        "Essential for debugging SPAs (Vue, React, Angular) where raw HTML contains "
        "unresolved template syntax. Supports mobile/tablet device emulation via the "
        "'device' parameter (e.g. 'Pixel 7', 'iPhone 14 Pro Max') for realistic "
        "responsive/visual review with the correct viewport, DPR, and touch."
    ),
    parameters={
        "url": {"type": "string", "description": "URL to render."},
        "wait": {"type": "integer", "description": "Milliseconds to wait for JS execution (default 5000).", "default": 5000},
        "execute": {"type": "string", "description": "Optional JavaScript to run after page loads."},
        "extract": {"type": "string", "description": "What to return: dom, console, errors, all (default all).", "default": "all"},
        "screenshot": {"type": "boolean", "description": "Take a screenshot (saved to /tmp).", "default": False},
        "screenshot_inline": {"type": "boolean", "description": "Return the screenshot inline as an image the client can display (base64 PNG). Default True when screenshot is taken. Large shots over ~4MB fall back to path-only.", "default": True},
        "ignore_https": {"type": "boolean", "description": "Ignore TLS cert errors (self-signed/expired/name-mismatch). Default True so internal apps behind bad certs still render.", "default": True},
        "device": {"type": "string", "description": "Emulate a device by Playwright registry name (e.g. 'Pixel 7', 'iPhone 14 Pro Max', 'iPad Pro 11'). Sets viewport, device-scale-factor, mobile user-agent and touch. Omit for desktop 1920x1080. Unknown names return the list of available devices."},
    },
)
async def ghost_render(
    url: str,
    wait: int = 5000,
    execute: Optional[str] = None,
    extract: str = "all",
    screenshot: bool = False,
    screenshot_inline: bool = True,
    ignore_https: bool = True,
    device: Optional[str] = None,
) -> str:
    """Render a page with headless browser and capture console output."""
    
    # For localhost URLs with a bridge connected, do a REAL navigation and
    # proxy every same-origin request through the bridge. This makes a
    # multi-file SPA (external js/css, /api XHRs, localStorage) actually load
    # and execute — unlike the old data: URL trick which broke all of that.
    if _should_use_bridge(url):
        from .recon.render import render_page as _render
        from urllib.parse import urlparse as _urlparse

        _target = _urlparse(url)
        _origin_host = _target.hostname
        _origin_port = _target.port or 80

        # Headers that must not be forwarded into route.fulfill (the browser
        # recomputes them; passing encoded/length headers corrupts the body).
        _strip = {"content-encoding", "content-length", "transfer-encoding",
                  "connection", "keep-alive"}

        async def _bridge_route(route, request):
            try:
                rp = _urlparse(request.url)
                same_origin = (
                    rp.hostname in ("localhost", "127.0.0.1", "0.0.0.0", "host.docker.internal")
                    and (rp.port or 80) == _origin_port
                )
                if not same_origin:
                    # External (CDN, fonts, etc.) — let the GhostMCP host fetch directly.
                    await route.continue_()
                    return
                resp = await _fetch_via_bridge(
                    request.url,
                    method=request.method,
                    headers=dict(request.headers),
                    body=request.post_data,
                )
                if "error" in resp:
                    await route.abort()
                    return
                hdrs = {k: v for k, v in (resp.get("headers") or {}).items()
                        if k.lower() not in _strip}
                await route.fulfill(
                    status=resp.get("status", 200),
                    headers=hdrs,
                    body=resp.get("body", "") or "",
                )
            except Exception:
                try:
                    await route.abort()
                except Exception:
                    pass

        report = await _render(
            url=url,
            wait_ms=wait,
            execute_js=execute,
            capture_screenshot=screenshot,
            route_handler=_bridge_route,
            device=device,
        )
        report.final_url = (report.final_url or url) + " (via bridge)"
    else:
        report = await render_page(
            url=url,
            wait_ms=wait,
            execute_js=execute,
            capture_screenshot=screenshot,
            ignore_https_errors=ignore_https,
            device=device,
        )

    if report.error:
        return f"Render error: {report.error}"

    lines = []

    if extract in ("all", "dom"):
        lines.append(f"=== Rendered Page: {report.title} ===")
        lines.append(f"URL: {report.final_url or report.url}")
        lines.append(f"Status: {report.status_code}")
        lines.append(f"Load time: {report.load_time_ms}ms")
        if report.device_info:
            di = report.device_info
            vp = di.get("viewport") or {}
            lines.append(
                f"Device: {di.get('device')} — {vp.get('width')}x{vp.get('height')} "
                f"@ DPR {di.get('device_scale_factor')} "
                f"(mobile={di.get('is_mobile')}, touch={di.get('has_touch')})"
            )
        lines.append("")
        # Truncate rendered HTML for context window sanity
        html = report.rendered_html
        if len(html) > 30000:
            html = html[:30000] + "\n\n[... truncated at 30KB ...]"
        lines.append(html)

    if extract in ("all", "console"):
        if report.console_log or report.console_errors:
            lines.append("\n=== Console Output ===")
            for msg in report.console_log:
                lines.append(f"  {msg}")
            for msg in report.console_errors:
                lines.append(f"  ** {msg}")

    if extract in ("all", "errors"):
        if report.js_errors:
            lines.append("\n=== JavaScript Errors ===")
            for err in report.js_errors:
                lines.append(f"  ERROR: {err}")
        elif extract == "errors":
            lines.append("No JavaScript errors detected.")

    text_body = "\n".join(lines) if lines else "Page rendered successfully but no content extracted."

    # Screenshot egress. When a screenshot was captured and inline return is
    # requested, read the PNG and emit it as an MCP image content block so the
    # client (and agent) can SEE it directly — no manual file copy needed.
    # Guard against oversized responses: PNGs above the cap fall back to path.
    if report.screenshot_path and screenshot:
        if screenshot_inline:
            try:
                import base64 as _b64
                import os as _os
                _MAX_INLINE_BYTES = 4 * 1024 * 1024  # ~4MB PNG cap
                _size = _os.path.getsize(report.screenshot_path)
                if _size <= _MAX_INLINE_BYTES:
                    with open(report.screenshot_path, "rb") as _f:
                        _b64png = _b64.b64encode(_f.read()).decode("ascii")
                    text_body += f"\n\nScreenshot ({_size} bytes) returned inline below. Also saved: {report.screenshot_path}"
                    return [
                        {"type": "text", "text": text_body},
                        {"type": "image", "data": _b64png, "mimeType": "image/png"},
                    ]
                else:
                    text_body += (
                        f"\n\nScreenshot saved: {report.screenshot_path} "
                        f"({_size} bytes — exceeds {_MAX_INLINE_BYTES}B inline cap, not embedded)"
                    )
            except Exception as _e:
                text_body += f"\n\nScreenshot saved: {report.screenshot_path} (inline encode failed: {_e})"
        else:
            text_body += f"\n\nScreenshot saved: {report.screenshot_path}"

    return text_body


# ---------------------------------------------------------------------------
# People Search tools — phone, email, username, VIN, court, breach, report
# ---------------------------------------------------------------------------

def _format_phone_report(r: PhoneReport) -> str:
    """Format phone lookup result as readable text."""
    if r.error:
        return f"Phone lookup error: {r.error}"
    lines = [f"=== Phone Intelligence: {r.number} ===", ""]
    if r.formatted:
        lines.append(f"E.164:         {r.formatted.get('e164', 'N/A')}")
        lines.append(f"National:      {r.formatted.get('national', 'N/A')}")
        lines.append(f"International: {r.formatted.get('international', 'N/A')}")
    lines.append(f"Valid:         {r.valid}")
    lines.append(f"Country:       {r.country} ({r.country_code})")
    if r.region:
        lines.append(f"Region:        {r.region}")
    if r.timezone:
        lines.append(f"Timezone:      {r.timezone}")
    lines.append(f"Carrier Type:  {r.carrier_type}")
    if r.carrier_name:
        lines.append(f"Carrier:       {r.carrier_name}")
    if r.cnam_name:
        lines.append(f"\nCaller Name (CNAM): {r.cnam_name}")
    if r.veriphone:
        lines.append(f"\nVeriphone:     {r.veriphone}")
    if r.search_urls:
        lines.append("\nSearch URLs:")
        for name, url in r.search_urls.items():
            lines.append(f"  {name}: {url}")
    return "\n".join(lines)


@mcp.tool(
    name="ghost_phone",
    description=(
        "Look up a phone number: validate, format, identify carrier type/name, "
        "timezone, and optionally resolve caller name via CNAM. Generates reverse-phone "
        "search URLs for manual investigation."
    ),
    parameters={
        "number": {"type": "string", "description": "Phone number in any format (e.g. +12145551234, (214) 555-1234)."},
        "country": {"type": "string", "description": "Default country code for parsing (default: US).", "default": "US"},
    },
)
async def ghost_phone(number: str, country: str = "US") -> str:
    if not number:
        return "Error: number is required."
    report = await phone_lookup(number, country=country)
    return _format_phone_report(report)


def _format_vehicle_report(r: VehicleReport) -> str:
    if r.error:
        return f"Vehicle lookup error: {r.error}"
    lines = [f"=== Vehicle Intelligence: {r.vin} ===", ""]
    lines.append(f"Make:          {r.make}")
    lines.append(f"Model:         {r.model}")
    lines.append(f"Year:          {r.year}")
    if r.trim:
        lines.append(f"Trim:          {r.trim}")
    if r.body_type:
        lines.append(f"Body Type:     {r.body_type}")
    if r.drive_type:
        lines.append(f"Drive Type:    {r.drive_type}")
    if r.transmission:
        lines.append(f"Transmission:  {r.transmission}")
    if r.engine:
        eng = r.engine
        lines.append(f"\nEngine:")
        if eng.get("displacement"):
            lines.append(f"  Displacement: {eng['displacement']}L")
        if eng.get("cylinders"):
            lines.append(f"  Cylinders:    {eng['cylinders']}")
        if eng.get("fuel_type"):
            lines.append(f"  Fuel Type:    {eng['fuel_type']}")
    if r.manufacturer:
        lines.append(f"\nManufacturer:  {r.manufacturer.get('name', 'N/A')}")
        if r.manufacturer.get("country"):
            lines.append(f"  Country:     {r.manufacturer['country']}")
    if r.safety_features:
        lines.append(f"\nSafety Features ({len(r.safety_features)}):")
        for feat in r.safety_features[:10]:
            lines.append(f"  - {feat}")
        if len(r.safety_features) > 10:
            lines.append(f"  ... and {len(r.safety_features) - 10} more")
    if r.recalls:
        lines.append(f"\nRecalls ({len(r.recalls)}):")
        for rc in r.recalls[:5]:
            lines.append(f"  Campaign: {rc.get('campaign_number', 'N/A')}")
            lines.append(f"    Component: {rc.get('component', 'N/A')}")
            lines.append(f"    Summary:   {rc.get('summary', 'N/A')[:120]}")
            lines.append("")
        if len(r.recalls) > 5:
            lines.append(f"  ... and {len(r.recalls) - 5} more recalls")
    else:
        lines.append("\nRecalls: None found")
    if r.complaint_count:
        lines.append(f"\nConsumer Complaints: {r.complaint_count}")
    if r.search_urls:
        lines.append("\nSearch URLs:")
        for name, url in r.search_urls.items():
            lines.append(f"  {name}: {url}")
    return "\n".join(lines)


@mcp.tool(
    name="ghost_vin",
    description=(
        "Decode a Vehicle Identification Number (VIN). Returns make, model, year, "
        "engine specs, safety features, manufacturer info, open recalls, and complaint "
        "count. Uses free NHTSA government APIs (no key required)."
    ),
    parameters={
        "vin": {"type": "string", "description": "Vehicle Identification Number (17 characters)."},
    },
)
async def ghost_vin(vin: str) -> str:
    if not vin:
        return "Error: vin is required."
    report = await vehicle_lookup(vin)
    return _format_vehicle_report(report)


def _format_people_report(r: PeopleSearchResult) -> str:
    lines = [f"=== People Search URLs: {r.query_type} ===", ""]
    lines.append(f"Input: {r.input_data}")
    lines.append(f"Total URLs generated: {r.total_urls}")
    lines.append("")
    for category, urls in r.search_urls.items():
        lines.append(f"--- {category} ---")
        for entry in urls:
            lines.append(f"  {entry.get('name', '?')}: {entry.get('url', '?')}")
        lines.append("")
    return "\n".join(lines)


@mcp.tool(
    name="ghost_people",
    description=(
        "Generate search URLs across 15+ people-search sites for a given name, phone, "
        "email, address, or username. Uses the IntelTechniques URL-generator approach: "
        "no scraping, no API calls — generates direct links for manual investigation. "
        "Covers people-search sites, social media, court records, and property records."
    ),
    parameters={
        "query_type": {
            "type": "string",
            "description": "Type of search: name, phone, email, address, username.",
        },
        "first": {"type": "string", "description": "First name (for name/address search)."},
        "last": {"type": "string", "description": "Last name (for name search)."},
        "phone": {"type": "string", "description": "Phone number (for phone search)."},
        "email": {"type": "string", "description": "Email address (for email search)."},
        "username": {"type": "string", "description": "Username (for username search)."},
        "street": {"type": "string", "description": "Street address (for address search)."},
        "city": {"type": "string", "description": "City (for name/address search)."},
        "state": {"type": "string", "description": "State abbreviation (for name/address search)."},
    },
)
async def ghost_people(
    query_type: str,
    first: str = "",
    last: str = "",
    phone: str = "",
    email: str = "",
    username: str = "",
    street: str = "",
    city: str = "",
    state: str = "",
) -> str:
    if not query_type:
        return "Error: query_type is required (name, phone, email, address, username)."
    # Only pass relevant kwargs per query_type to avoid TypeError
    kwargs: dict = {}
    qt = query_type.strip().lower()
    if qt == "name":
        kwargs = {"first": first, "last": last, "city": city, "state": state}
    elif qt == "phone":
        kwargs = {"phone": phone}
    elif qt == "email":
        kwargs = {"email": email}
    elif qt == "address":
        kwargs = {"street": street, "city": city, "state": state}
    elif qt == "username":
        kwargs = {"username": username}
    else:
        return f"Error: unknown query_type '{query_type}'. Use: name, phone, email, address, username."
    report = await people_search(query_type=query_type, **kwargs)
    return _format_people_report(report)


def _format_email_report(r: EmailReport) -> str:
    if getattr(r, "error", None):
        return f"Email lookup error: {r.error}"
    lines = [f"=== Email Intelligence: {r.email} ===", ""]
    lines.append(f"Domain:          {r.domain}")
    lines.append(f"Free Provider:   {r.is_free_provider}")
    if r.reputation:
        rep = r.reputation
        lines.append(f"\nReputation:")
        lines.append(f"  Score:         {rep.get('reputation', 'N/A')}")
        lines.append(f"  Suspicious:    {rep.get('suspicious', 'N/A')}")
        if rep.get('details'):
            details = rep['details']
            if isinstance(details, dict):
                for k, v in list(details.items())[:8]:
                    lines.append(f"  {k}: {v}")
    if r.breach_count is not None:
        lines.append(f"\nBreach Exposure: {r.breach_count} breaches")
        if r.breaches:
            for b in r.breaches[:10]:
                lines.append(f"  - {b}")
            if len(r.breaches) > 10:
                lines.append(f"  ... and {len(r.breaches) - 10} more")
    if r.accounts_found:
        lines.append(f"\nAccounts Found ({len(r.accounts_found)} sites):")
        for a in r.accounts_found[:15]:
            lines.append(f"  - {a}")
        if len(r.accounts_found) > 15:
            lines.append(f"  ... and {len(r.accounts_found) - 15} more")
    if r.hunter_enrichment:
        h = r.hunter_enrichment
        lines.append(f"\nProfessional Enrichment (Hunter.io):")
        if h.get("first_name"):
            lines.append(f"  Name:     {h.get('first_name', '')} {h.get('last_name', '')}")
        if h.get("position"):
            lines.append(f"  Position: {h['position']}")
        if h.get("company"):
            lines.append(f"  Company:  {h['company']}")
        if h.get("linkedin_url"):
            lines.append(f"  LinkedIn: {h['linkedin_url']}")
        if h.get("twitter"):
            lines.append(f"  Twitter:  {h['twitter']}")
    if r.errors:
        lines.append(f"\nProvider Errors:")
        for svc, err in r.errors.items():
            lines.append(f"  {svc}: {err}")
    if r.search_urls:
        lines.append("\nSearch URLs:")
        for name, url in r.search_urls.items():
            lines.append(f"  {name}: {url}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# GIS Property Lookup Tool
# ---------------------------------------------------------------------------

def _format_gis_result(r: GISResult) -> str:
    """Format GIS lookup result as readable text."""
    lines = [f"=== Property Record: {r.address or r.parcel_id} ===", ""]
    
    # Property identification
    lines.append("PROPERTY")
    if r.parcel_id:
        lines.append(f"  Parcel ID:     {r.parcel_id}")
    if r.address:
        addr_line = r.address
        if r.city:
            addr_line += f", {r.city}"
        if r.state:
            addr_line += f", {r.state}"
        if r.zip_code:
            addr_line += f" {r.zip_code}"
        lines.append(f"  Address:       {addr_line}")
    if r.county:
        lines.append(f"  County:        {r.county}")
    if r.coordinates[0]:
        lines.append(f"  Coordinates:   {r.coordinates[0]:.6f}, {r.coordinates[1]:.6f}")
    
    # Land info
    if r.acreage or r.zoning or r.land_use:
        lines.append("")
        lines.append("LAND")
        if r.acreage:
            lines.append(f"  Acreage:       {r.acreage:.2f} acres")
        if r.zoning:
            lines.append(f"  Zoning:        {r.zoning}")
        if r.land_use:
            lines.append(f"  Land Use:      {r.land_use}")
        if r.legal_description:
            lines.append(f"  Legal Desc:    {r.legal_description[:100]}...")
    
    # Valuation
    if r.total_value or r.land_value:
        lines.append("")
        lines.append("VALUATION")
        if r.land_value:
            lines.append(f"  Land Value:    ${r.land_value:,.0f}")
        if r.improvement_value:
            lines.append(f"  Improvements:  ${r.improvement_value:,.0f}")
        if r.total_value:
            lines.append(f"  Total Value:   ${r.total_value:,.0f}")
        if r.tax_year:
            lines.append(f"  Tax Year:      {r.tax_year}")
    
    # Building info
    if r.year_built or r.building_sqft:
        lines.append("")
        lines.append("BUILDING")
        if r.year_built:
            lines.append(f"  Year Built:    {r.year_built}")
        if r.building_sqft:
            lines.append(f"  Square Feet:   {r.building_sqft:,}")
        if r.bedrooms:
            lines.append(f"  Bedrooms:      {r.bedrooms}")
        if r.bathrooms:
            lines.append(f"  Bathrooms:     {r.bathrooms}")
    
    # Owner info
    if r.owner_name:
        lines.append("")
        lines.append("OWNER")
        lines.append(f"  Name:          {r.owner_name}")
        lines.append(f"  Type:          {r.owner_type}")
        if r.mailing_address:
            mail_line = r.mailing_address
            if r.mailing_city:
                mail_line += f", {r.mailing_city}"
            if r.mailing_state:
                mail_line += f", {r.mailing_state}"
            if r.mailing_zip:
                mail_line += f" {r.mailing_zip}"
            lines.append(f"  Mailing Addr:  {mail_line}")
    
    # Enrichment (alternate addresses, phones, emails)
    if r.alternate_addresses:
        lines.append("")
        lines.append("ALTERNATE ADDRESSES")
        for addr in r.alternate_addresses[:5]:
            lines.append(f"  - {addr}")
    
    if r.phone_numbers:
        lines.append("")
        lines.append("PHONE NUMBERS")
        for phone in r.phone_numbers[:5]:
            lines.append(f"  - {phone}")
    
    if r.email_addresses:
        lines.append("")
        lines.append("EMAIL ADDRESSES")
        for email in r.email_addresses[:5]:
            lines.append(f"  - {email}")
    
    if r.associated_names:
        lines.append("")
        lines.append("ASSOCIATED NAMES")
        for name in r.associated_names[:5]:
            lines.append(f"  - {name}")
    
    # Investigation URLs
    if r.search_urls:
        lines.append("")
        lines.append("INVESTIGATION URLS")
        for name, url in r.search_urls.items():
            lines.append(f"  {name}: {url}")
    
    # Source
    lines.append("")
    lines.append(f"Source: {r.source}")
    
    return "\n".join(lines)


@mcp.tool(
    name="ghost_gis",
    description=(
        "Look up property/parcel data by address, coordinates, or parcel ID. "
        "Returns owner name, mailing address, assessed value, zoning, acreage, "
        "and building info. Generates investigation URLs for owner enrichment. "
        "Supports Regrid API (nationwide, requires GHOST_REGRID_KEY) or state "
        "GIS endpoints (TX, NY, FL, CO — free, no key)."
    ),
    parameters={
        "address": {
            "type": "string",
            "description": "Street address to look up (e.g., '123 Main St, Austin, TX 78701').",
            "default": "",
        },
        "lat": {
            "type": "number",
            "description": "Latitude (WGS84). Use with lon for coordinate lookup.",
            "default": 0,
        },
        "lon": {
            "type": "number",
            "description": "Longitude (WGS84). Use with lat for coordinate lookup.",
            "default": 0,
        },
        "parcel_id": {
            "type": "string",
            "description": "Parcel ID / APN. Requires state (and optionally county).",
            "default": "",
        },
        "county": {
            "type": "string",
            "description": "County name (helps disambiguate parcel_id lookups).",
            "default": "",
        },
        "state": {
            "type": "string",
            "description": "State abbreviation (e.g., 'TX', 'NY'). Required for state GIS or parcel_id lookup.",
            "default": "",
        },
        "provider": {
            "type": "string",
            "description": (
                "Data provider: 'auto' (try Regrid then state), 'regrid' (nationwide, needs key), "
                "'state' (use state endpoint), or specific state code ('TX', 'NY', 'FL', 'CO')."
            ),
            "default": "auto",
        },
    },
)
async def ghost_gis(
    address: str = "",
    lat: float = 0,
    lon: float = 0,
    parcel_id: str = "",
    county: str = "",
    state: str = "",
    provider: str = "auto",
) -> str:
    """Look up property/parcel data with owner information."""
    # Validate input
    if not address and not (lat and lon) and not parcel_id:
        return (
            "Error: Must provide one of:\n"
            "  - address (e.g., '123 Main St, Austin, TX')\n"
            "  - lat + lon coordinates\n"
            "  - parcel_id + state"
        )
    
    if parcel_id and not state:
        return "Error: parcel_id lookup requires state parameter."
    
    try:
        result = await gis_lookup(
            address=address,
            lat=float(lat),
            lon=float(lon),
            parcel_id=parcel_id,
            county=county,
            state=state,
            provider=provider,
        )
        return _format_gis_result(result)
    except GISError as e:
        return f"GIS lookup error: {e}"
    except Exception as e:
        return f"Unexpected error: {e}"


@mcp.tool(
    name="ghost_email",
    description=(
        "Investigate an email address: reputation scoring, breach exposure, account "
        "discovery (which sites it's registered on), and professional enrichment "
        "(name, company, title via Hunter.io). Generates OSINT search URLs."
    ),
    parameters={
        "email": {"type": "string", "description": "Email address to investigate."},
        "include_holehe": {
            "type": "boolean",
            "description": "Run Holehe account discovery — finds which sites the email is registered on. Slow (2-5 min). Default: true.",
            "default": True,
        },
        "include_hunter": {
            "type": "boolean",
            "description": "Run Hunter.io professional enrichment (requires GHOST_HUNTER_KEY, costs 1 API credit). Only runs on non-free-provider domains. Default: false.",
            "default": False,
        },
    },
)
async def ghost_email(
    email: str,
    include_holehe: bool = True,
    include_hunter: bool = False,
) -> str:
    if not email:
        return "Error: email is required."
    report = await email_lookup(email, include_holehe=include_holehe, include_hunter=include_hunter)
    return _format_email_report(report)


def _format_username_report(r: UsernameReport) -> str:
    if r.error:
        return f"Username lookup error: {r.error}"
    lines = [f"=== Username Enumeration: {r.username} ===", ""]
    lines.append(f"Tool Used:      {r.tool_used}")
    lines.append(f"Sites Checked:  {r.sites_checked}")
    lines.append(f"Accounts Found: {len(r.accounts_found)}")
    lines.append(f"Scan Time:      {r.scan_time_seconds:.1f}s")
    if r.timed_out:
        lines.append("WARNING: Scan timed out — results may be incomplete")
    if r.accounts_found:
        lines.append("")
        # Group by category if available
        by_cat: dict[str, list] = {}
        for acct in r.accounts_found:
            cat = acct.get("category", "other")
            by_cat.setdefault(cat, []).append(acct)
        for cat, accts in sorted(by_cat.items()):
            lines.append(f"--- {cat} ({len(accts)}) ---")
            for a in accts:
                lines.append(f"  {a.get('site_name', '?')}: {a.get('url', '?')}")
            lines.append("")
    if r.search_urls:
        lines.append("Search URLs:")
        for name, url in r.search_urls.items():
            lines.append(f"  {name}: {url}")
    return "\n".join(lines)


@mcp.tool(
    name="ghost_username",
    description=(
        "Enumerate which platforms a username exists on. Uses Maigret (2500+ sites), "
        "Sherlock (400+ sites), or a built-in checker (20 major platforms) as fallback. "
        "Returns found accounts with URLs and categories."
    ),
    parameters={
        "username": {"type": "string", "description": "Username to search for."},
        "max_sites": {
            "type": "integer",
            "description": "Maximum sites to check (default 100, reduces scan time).",
            "default": 100,
        },
        "timeout": {
            "type": "integer",
            "description": "Maximum scan time in seconds (default 120). Returns partial results on timeout.",
            "default": 120,
        },
    },
)
async def ghost_username(
    username: str,
    max_sites: int = 100,
    timeout: int = 120,
) -> str:
    if not username:
        return "Error: username is required."
    report = await username_lookup(username, max_sites=max_sites, timeout=timeout)
    return _format_username_report(report)


def _format_court_report(r: CourtSearchResult) -> str:
    if r.error:
        return f"Court search error: {r.error}"
    lines = [f"=== Court Records: {r.query} ===", ""]
    lines.append(f"Total Results: {r.total_results}")
    if r.cases:
        lines.append("")
        for i, c in enumerate(r.cases[:10], 1):
            lines.append(f"--- Case {i} ---")
            lines.append(f"  Case Name:    {c.case_name}")
            if c.docket_number:
                lines.append(f"  Docket:       {c.docket_number}")
            lines.append(f"  Court:        {c.court}")
            if c.date_filed:
                lines.append(f"  Filed:        {c.date_filed}")
            if c.date_terminated:
                lines.append(f"  Terminated:   {c.date_terminated}")
            if c.nature_of_suit:
                lines.append(f"  Nature:       {c.nature_of_suit}")
            if c.parties:
                lines.append(f"  Parties:      {', '.join(c.parties[:5])}")
            if c.source_url:
                lines.append(f"  URL:          {c.source_url}")
            lines.append("")
        if r.total_results > 10:
            lines.append(f"... {r.total_results - 10} more results")
    elif r.total_results == 0:
        lines.append("\nNo cases found.")
    if r.search_urls:
        lines.append("\nSearch URLs:")
        for name, url in r.search_urls.items():
            lines.append(f"  {name}: {url}")
    return "\n".join(lines)


@mcp.tool(
    name="ghost_court",
    description=(
        "Search court records by party name or docket number. Uses CourtListener "
        "REST API for federal court cases (requires free API token via "
        "GHOST_COURTLISTENER_TOKEN). Falls back to search URL generation if no token."
    ),
    parameters={
        "query": {"type": "string", "description": "Person name or docket number to search."},
        "search_type": {
            "type": "string",
            "description": "Search type: party (search by name) or docket (search by docket number). Default: party.",
            "default": "party",
        },
    },
)
async def ghost_court(query: str, search_type: str = "party") -> str:
    if not query:
        return "Error: query is required."
    report = await court_search(query, search_type=search_type)
    return _format_court_report(report)


def _format_breach_report(r: BreachSearchResult) -> str:
    if r.error:
        return f"Breach search error: {r.error}"
    lines = [f"=== Breach Search: {r.query} ({r.query_type}) ===", ""]
    lines.append(f"Mode:            {r.mode}")
    lines.append(f"Total Breaches:  {r.total_breaches}")
    lines.append(f"Providers OK:    {', '.join(r.providers_checked) or 'none'}")
    if r.providers_failed:
        lines.append(f"Providers Failed: {', '.join(f'{k}: {v}' for k, v in r.providers_failed.items())}")
    if r.records:
        lines.append("")
        # Group by severity
        by_sev: dict[str, list] = {}
        for rec in r.records:
            by_sev.setdefault(rec.severity, []).append(rec)
        for sev in ["critical", "high", "medium", "low"]:
            recs = by_sev.get(sev, [])
            if recs:
                lines.append(f"--- {sev.upper()} ({len(recs)}) ---")
                for rec in recs[:5]:
                    lines.append(f"  {rec.breach_name} ({rec.source})")
                    if rec.date:
                        lines.append(f"    Date: {rec.date}")
                    if rec.data_classes:
                        lines.append(f"    Data: {', '.join(rec.data_classes[:6])}")
                    if rec.record_count:
                        lines.append(f"    Records: {rec.record_count:,}")
                    if rec.details and r.mode == "full":
                        lines.append(f"    Details: {rec.details}")
                    lines.append("")
                if len(recs) > 5:
                    lines.append(f"  ... and {len(recs) - 5} more {sev} breaches")
    elif r.total_breaches == 0:
        lines.append("\nNo breaches found.")
    if r.search_urls:
        lines.append("\nSearch URLs:")
        for name, url in r.search_urls.items():
            lines.append(f"  {name}: {url}")
    return "\n".join(lines)


@mcp.tool(
    name="ghost_breach",
    description=(
        "Search breach databases for exposed credentials and PII. Two modes: "
        "'metadata_only' (default, HIBP — which breaches, no PII) and 'full' "
        "(Snusbase/DeHashed/LeakCheck — actual breach records). "
        "Search by email, phone, username, name, or IP."
    ),
    parameters={
        "query": {"type": "string", "description": "Search query (email, phone, username, name, or IP)."},
        "query_type": {
            "type": "string",
            "description": "Query type: email, phone, username, name, ip. Default: email.",
            "default": "email",
        },
        "mode": {
            "type": "string",
            "description": "Search mode: metadata_only (HIBP, safe/legal) or full (breach records with PII, requires API keys). Default: metadata_only.",
            "default": "metadata_only",
        },
    },
)
async def ghost_breach(
    query: str,
    query_type: str = "email",
    mode: str = "metadata_only",
) -> str:
    if not query:
        return "Error: query is required."
    report = await breach_search(query, query_type=query_type, mode=mode)
    return _format_breach_report(report)


def _format_ip_report(r: IPReport) -> str:
    """Format IP lookup result as readable text."""
    if r.error:
        return f"IP lookup error: {r.error}"
    lines = [f"=== IP Intelligence: {r.ip} ===", ""]
    lines.append(f"Valid:         {r.valid}")
    if r.country:
        lines.append(f"Country:       {r.country} ({r.country_code})")
    if r.region_name:
        lines.append(f"Region:        {r.region_name} ({r.region})")
    if r.city:
        lines.append(f"City:          {r.city}")
    if r.zip_code:
        lines.append(f"ZIP:           {r.zip_code}")
    if r.latitude is not None:
        lines.append(f"Coordinates:   {r.latitude}, {r.longitude}")
    if r.timezone:
        lines.append(f"Timezone:      {r.timezone}")
    lines.append("")
    if r.isp:
        lines.append(f"ISP:           {r.isp}")
    if r.org:
        lines.append(f"Organization:  {r.org}")
    if r.asn:
        lines.append(f"ASN:           {r.asn}")
    if r.as_name:
        lines.append(f"AS Name:       {r.as_name}")
    if r.reverse_dns:
        lines.append(f"Reverse DNS:   {r.reverse_dns}")
    lines.append("")
    flags = []
    if r.is_mobile:
        flags.append("MOBILE")
    if r.is_proxy:
        flags.append("PROXY/VPN")
    if r.is_hosting:
        flags.append("HOSTING/DATACENTER")
    if flags:
        lines.append(f"Flags:         {', '.join(flags)}")
    else:
        lines.append("Flags:         None (residential)")
    if r.threat_hits:
        lines.append(f"\nThreat Hits ({len(r.threat_hits)}):")
        for hit in r.threat_hits[:5]:
            lines.append(f"  - {hit}")
    if r.search_urls:
        lines.append("\nSearch URLs:")
        for name, url in r.search_urls.items():
            lines.append(f"  {name}: {url}")
    return "\n".join(lines)


@mcp.tool(
    name="ghost_ip",
    description=(
        "Look up an IP address: geolocation (country, city, coordinates), ISP/ASN, "
        "organization, reverse DNS, and proxy/VPN/hosting detection. Uses ip-api.com "
        "(free, no key, 45 req/min). Generates investigation URLs for Shodan, "
        "AbuseIPDB, GreyNoise, VirusTotal, Censys, and more."
    ),
    parameters={
        "ip": {"type": "string", "description": "IPv4 or IPv6 address to investigate."},
    },
)
async def ghost_ip(ip: str) -> str:
    if not ip:
        return "Error: ip is required."
    report = await ip_lookup(ip)
    return _format_ip_report(report)


# ---------------------------------------------------------------------------
# DNS intelligence tool
# ---------------------------------------------------------------------------

def _format_dns_report(r: DNSReport) -> str:
    """Format a DNSReport into readable text."""
    if r.error:
        return f"DNS lookup error: {r.error}"

    lines = [f"=== DNS Intelligence: {r.domain} ===", ""]

    # Core records
    if r.a_records:
        lines.append(f"A Records ({len(r.a_records)}):")
        for ip in r.a_records:
            lines.append(f"  {ip}")
        lines.append("")

    if r.aaaa_records:
        lines.append(f"AAAA Records ({len(r.aaaa_records)}):")
        for ip in r.aaaa_records:
            lines.append(f"  {ip}")
        lines.append("")

    if r.cname_records:
        lines.append(f"CNAME Records ({len(r.cname_records)}):")
        for cn in r.cname_records:
            lines.append(f"  {cn}")
        lines.append("")

    if r.mx_records:
        lines.append(f"MX Records ({len(r.mx_records)}):")
        for mx in r.mx_records:
            lines.append(f"  [{mx['priority']}] {mx['host']}")
        lines.append("")

    if r.ns_records:
        lines.append(f"NS Records ({len(r.ns_records)}):")
        for ns in r.ns_records:
            lines.append(f"  {ns}")
        lines.append("")

    if r.txt_records:
        lines.append(f"TXT Records ({len(r.txt_records)}):")
        for txt in r.txt_records:
            lines.append(f"  {txt}")
        lines.append("")

    if r.srv_records:
        lines.append(f"SRV Records ({len(r.srv_records)}):")
        for srv in r.srv_records:
            lines.append(
                f"  {srv['service']}.{srv['protocol']} -> "
                f"{srv['target']}:{srv['port']} "
                f"(pri={srv['priority']} w={srv['weight']})"
            )
        lines.append("")

    if r.caa_records:
        lines.append(f"CAA Records ({len(r.caa_records)}):")
        for caa in r.caa_records:
            lines.append(f"  {caa}")
        lines.append("")

    if r.soa_record:
        lines.append(f"SOA: {r.soa_record}")
        lines.append("")

    # Email security
    lines.append(f"Email Security Grade: {r.email_security_grade}")
    lines.append("")

    if r.spf:
        lines.append(f"SPF: {r.spf.get('record', 'N/A')}")
        lines.append(f"  Valid: {r.spf.get('valid', 'N/A')}")
        lines.append(f"  DNS Lookups: {r.spf.get('mechanism_count', 0)}/10")
        if r.spf.get("includes"):
            lines.append(f"  Includes: {', '.join(r.spf['includes'])}")
        for issue in r.spf.get("issues", []):
            lines.append(f"  ** {issue}")
        lines.append("")

    if r.dmarc:
        lines.append(f"DMARC: {r.dmarc.get('record', 'N/A')}")
        lines.append(f"  Policy: {r.dmarc.get('policy', 'N/A')}")
        lines.append(f"  Pct: {r.dmarc.get('pct', 'N/A')}%")
        if r.dmarc.get("rua"):
            lines.append(f"  Report URI: {r.dmarc['rua']}")
        for issue in r.dmarc.get("issues", []):
            lines.append(f"  ** {issue}")
        lines.append("")

    if r.dkim:
        if r.dkim.get("found"):
            lines.append(f"DKIM: Found (selector={r.dkim['selector']})")
            lines.append(f"  {r.dkim.get('record', '')[:100]}...")
        else:
            lines.append("DKIM: Not found")
            for issue in r.dkim.get("issues", []):
                lines.append(f"  ** {issue}")
        lines.append("")

    # Dangling CNAMEs
    if r.dangling_cnames:
        lines.append(f"Dangling CNAMEs ({len(r.dangling_cnames)}):")
        for dc in r.dangling_cnames:
            lines.append(
                f"  {dc['cname']} -> {dc['target']} "
                f"[{dc['status']}] RISK: {dc['risk'].upper()}"
            )
        lines.append("")

    # Service discovery
    if r.service_discovery:
        lines.append(f"Services Discovered ({len(r.service_discovery)}):")
        for svc in r.service_discovery:
            lines.append(f"  [{svc['from_record_type']}] {svc['service']}")
        lines.append("")

    return "\n".join(lines)


@mcp.tool(
    name="ghost_dns",
    description=(
        "Comprehensive DNS reconnaissance on a domain. Enumerates all record types "
        "(A, AAAA, MX, NS, CNAME, TXT, SRV, CAA, SOA) via DNS-over-HTTPS. Analyzes "
        "email security posture (SPF/DMARC/DKIM grading A-F), detects dangling CNAMEs "
        "for subdomain takeover, and discovers SaaS services from TXT/SRV records."
    ),
    parameters={
        "domain": {
            "type": "string",
            "description": "Target domain to investigate (e.g. example.com).",
        },
    },
)
async def ghost_dns(domain: str) -> str:
    """Comprehensive DNS reconnaissance on a domain."""
    if not domain:
        return "Error: domain is required."
    report = await dns_lookup(domain)
    return _format_dns_report(report)


# ---------------------------------------------------------------------------
# ASN / BGP infrastructure tool
# ---------------------------------------------------------------------------

def _format_asn_report(r: ASNReport) -> str:
    """Format an ASNReport into readable text."""
    if r.error:
        return f"ASN lookup error: {r.error}"

    lines: list[str] = [f"=== ASN Intelligence: AS{r.asn} ===", ""]

    if r.asn_name:
        lines.append(f"Name:           {r.asn_name}")
    if r.description:
        lines.append(f"Description:    {r.description}")
    if r.country_code:
        lines.append(f"Country:        {r.country_code}")
    if r.rir:
        lines.append(f"RIR:            {r.rir}")
    if r.allocation_date:
        lines.append(f"Allocated:      {r.allocation_date}")
    if r.abuse_contact:
        lines.append(f"Abuse Contact:  {r.abuse_contact}")

    lines.append("")
    lines.append(f"IPv4 Prefixes:  {r.prefix_count_v4}")
    lines.append(f"IPv6 Prefixes:  {r.prefix_count_v6}")

    if r.prefixes_v4:
        lines.append("")
        lines.append("--- IPv4 Prefixes ---")
        for p in r.prefixes_v4[:20]:
            desc = f" ({p['description']})" if p.get("description") else ""
            lines.append(f"  {p['prefix']}{desc}")
        if len(r.prefixes_v4) > 20:
            lines.append(f"  ... and {len(r.prefixes_v4) - 20} more")

    if r.prefixes_v6:
        lines.append("")
        lines.append("--- IPv6 Prefixes ---")
        for p in r.prefixes_v6[:10]:
            desc = f" ({p['description']})" if p.get("description") else ""
            lines.append(f"  {p['prefix']}{desc}")
        if len(r.prefixes_v6) > 10:
            lines.append(f"  ... and {len(r.prefixes_v6) - 10} more")

    if r.upstream_peers:
        lines.append("")
        lines.append(f"--- Upstream Peers ({len(r.upstream_peers)}) ---")
        for p in r.upstream_peers[:15]:
            lines.append(f"  AS{p['asn']} {p['name']} — {p['description']}")

    if r.downstream_peers:
        lines.append("")
        lines.append(f"--- Downstream Peers ({len(r.downstream_peers)}) ---")
        for p in r.downstream_peers[:15]:
            lines.append(f"  AS{p['asn']} {p['name']} — {p['description']}")

    if r.ix_presence:
        lines.append("")
        lines.append(f"--- IX Presence ({len(r.ix_presence)}) ---")
        for ix in r.ix_presence[:15]:
            speed = f" ({ix['speed']}Mbps)" if ix.get("speed") else ""
            lines.append(f"  {ix['name']} — {ix['city']}, {ix['country']}{speed}")

    if r.investigation_urls:
        lines.append("")
        lines.append("Investigation URLs:")
        for name, url in r.investigation_urls.items():
            lines.append(f"  {name}: {url}")

    return "\n".join(lines)


@mcp.tool(
    name="ghost_asn",
    description=(
        "Look up BGP/ASN network infrastructure: announced prefixes, upstream/downstream "
        "peers, IX presence, RIR allocation, and abuse contacts. Accepts an ASN number "
        "(e.g. AS15169), IP address, or organisation name. Uses free BGPView API."
    ),
    parameters={
        "query": {
            "type": "string",
            "description": "ASN number (e.g. 15169 or AS15169), IP address, or organisation name.",
        },
        "query_type": {
            "type": "string",
            "description": 'Query type: "asn", "ip", or "org". Auto-detected if empty.',
            "default": "",
        },
    },
)
async def ghost_asn(query: str, query_type: str = "") -> str:
    """Look up BGP/ASN network infrastructure."""
    if not query:
        return "Error: query is required."
    report = await asn_lookup(query, query_type=query_type)
    return _format_asn_report(report)


def _format_headers_report(r: HeadersReport) -> str:
    """Format a HeadersReport into readable text."""
    if r.error:
        return f"Header analysis error: {r.error}"

    lines: list[str] = []
    lines.append(f"=== HTTP Security Headers: {r.url} ===")
    lines.append(f"Grade: {r.grade} ({r.score}/100)")
    lines.append("")

    # Server fingerprint
    if r.server:
        lines.append(f"Server:        {r.server}")
    if r.x_powered_by:
        lines.append(f"X-Powered-By:  {r.x_powered_by}")
    if r.server or r.x_powered_by:
        lines.append("")

    # Present headers
    if r.headers_present:
        lines.append(f"Headers Present ({len(r.headers_present)}):")
        for name, info in r.headers_present.items():
            lines.append(f"  {name}: {info['score']}/{info['max']} — {info.get('detail', info.get('value', ''))}")
        lines.append("")

    # Missing headers
    if r.headers_missing:
        lines.append(f"Headers Missing ({len(r.headers_missing)}):")
        for name in r.headers_missing:
            lines.append(f"  - {name}")
        lines.append("")

    # CORS analysis
    if r.cors and r.cors.get("allow_origin"):
        lines.append("CORS:")
        for k, v in r.cors.items():
            if k in ("wildcard_origin", "wildcard_with_credentials") and not v:
                continue
            lines.append(f"  {k}: {v}")
        lines.append("")

    # Warnings
    if r.warnings:
        lines.append(f"Warnings ({len(r.warnings)}):")
        for w in r.warnings:
            lines.append(f"  ! {w}")
        lines.append("")

    return "\n".join(lines)


@mcp.tool(
    name="ghost_headers",
    description=(
        "Analyze HTTP security headers of a URL. Grades headers A+ through F, "
        "checks CSP, HSTS, CORS, X-Frame-Options, Permissions-Policy, and more. "
        "Detects server fingerprints and flags misconfigurations."
    ),
    parameters={
        "url": {"type": "string", "description": "URL to analyze."},
    },
)
async def ghost_headers(url: str) -> str:
    """Analyze HTTP security headers and grade them."""
    if not url:
        return "Error: url is required."
    report = await analyze_headers(url)
    return _format_headers_report(report)


def _format_background_report(r: BackgroundReport) -> str:
    """The report module already generates markdown — just return it."""
    return r.report_text


@mcp.tool(
    name="ghost_report",
    description=(
        "Generate a composite background report on a person by combining results "
        "from phone, email, username, VIN, court, and breach searches. Provide the "
        "subject's known identifiers and the tool will run all available searches "
        "and cross-reference the results into a structured OSINT dossier."
    ),
    parameters={
        "name": {"type": "string", "description": "Subject's full name (first last)."},
        "email": {"type": "string", "description": "Subject's email address."},
        "phone": {"type": "string", "description": "Subject's phone number."},
        "username": {"type": "string", "description": "Subject's online username."},
        "vin": {"type": "string", "description": "Subject's vehicle VIN."},
        "city": {"type": "string", "description": "Subject's city."},
        "state": {"type": "string", "description": "Subject's state."},
    },
)
async def ghost_report(
    name: str = "",
    email: str = "",
    phone: str = "",
    username: str = "",
    vin: str = "",
    city: str = "",
    state: str = "",
) -> str:
    if not any([name, email, phone, username, vin]):
        return "Error: at least one identifier is required (name, email, phone, username, or vin)."

    # Run all available searches in parallel
    tasks = {}
    if phone:
        tasks["phone"] = phone_lookup(phone)
    if email:
        tasks["email"] = email_lookup(email, include_holehe=False, include_hunter=True)
    if username:
        tasks["username"] = username_lookup(username, max_sites=50, timeout=60)
    if vin:
        tasks["vin"] = vehicle_lookup(vin)
    if name:
        parts = name.strip().split(None, 1)
        first = parts[0] if parts else ""
        last = parts[1] if len(parts) > 1 else ""
        tasks["court"] = court_search(name)
        tasks["people"] = people_search(
            query_type="name", first=first, last=last, city=city, state=state,
        )
    if email:
        tasks["breach"] = breach_search(email, query_type="email", mode="metadata_only")

    # Execute all tasks in parallel
    results = {}
    if tasks:
        keys = list(tasks.keys())
        completed = await asyncio.gather(*tasks.values(), return_exceptions=True)
        for k, v in zip(keys, completed):
            if isinstance(v, Exception):
                results[k] = None
            else:
                results[k] = v

    # Build subject dict
    subject = {}
    if name:
        subject["name"] = name
    if email:
        subject["email"] = email
    if phone:
        subject["phone"] = phone
    if username:
        subject["username"] = username
    if city:
        subject["city"] = city
    if state:
        subject["state"] = state

    # Generate composite report
    report = generate_report(
        subject=subject,
        phone_result=results.get("phone"),
        email_result=results.get("email"),
        username_result=results.get("username"),
        vehicle_result=results.get("vin"),
        court_result=results.get("court"),
        breach_result=results.get("breach"),
        people_urls=results.get("people"),
    )
    return _format_background_report(report)


# ---------------------------------------------------------------------------
# API surface discovery tool
# ---------------------------------------------------------------------------

def _format_api_discovery_report(r: APIDiscoveryReport) -> str:
    """Format an APIDiscoveryReport into readable text."""
    if r.error:
        return f"API Discovery error for {r.url}: {r.error}"

    lines: list[str] = []
    lines.append(f"=== API Surface Discovery: {r.url} ===")
    lines.append("")

    # OpenAPI / Swagger
    if r.openapi_found:
        lines.append(f"[OpenAPI] Found: {r.openapi_url}")
        lines.append(f"  Version:    {r.openapi_version}")
        if r.openapi_title:
            lines.append(f"  Title:      {r.openapi_title}")
        lines.append(f"  Endpoints:  {r.openapi_endpoints_count}")
        if r.openapi_paths:
            lines.append(f"  Paths ({len(r.openapi_paths)}):")
            for p in r.openapi_paths:
                lines.append(f"    {p}")
        lines.append("")
    else:
        lines.append("[OpenAPI] Not found")
        lines.append("")

    # GraphQL
    if r.graphql_found:
        lines.append(f"[GraphQL] Found: {r.graphql_url}")
        lines.append(f"  Introspection: {'enabled' if r.graphql_introspection else 'disabled'}")
        if r.graphql_introspection:
            lines.append(f"  Types:     {r.graphql_types_count}")
            if r.graphql_queries:
                lines.append(f"  Queries:   {', '.join(r.graphql_queries)}")
            if r.graphql_mutations:
                lines.append(f"  Mutations: {', '.join(r.graphql_mutations)}")
        lines.append("")

    # OIDC
    if r.oidc_found:
        lines.append(f"[OIDC] Provider: {r.oidc_provider}")
        lines.append(f"  Issuer: {r.oidc_issuer}")
        for ep_name, ep_url in r.oidc_endpoints.items():
            if ep_url:
                lines.append(f"  {ep_name}: {ep_url}")
        lines.append("")

    # Framework
    if r.framework:
        lines.append(f"[Framework] {r.framework}")
        if r.framework_evidence:
            lines.append(f"  Evidence: {r.framework_evidence}")
        lines.append("")

    # CORS
    if r.cors_policy:
        lines.append("[CORS Policy]")
        for k, v in r.cors_policy.items():
            lines.append(f"  {k}: {v}")
        lines.append("")

    # API Versions
    if r.api_versions:
        lines.append(f"[API Versions] ({len(r.api_versions)} detected)")
        for v in r.api_versions:
            lines.append(f"  {v['version']} — {v['path']} ({v['status']})")
        lines.append("")

    # robots.txt
    if r.robots_disallowed:
        lines.append(f"[robots.txt] {len(r.robots_disallowed)} disallowed paths")
        for p in r.robots_disallowed[:15]:
            lines.append(f"  {p}")
        if len(r.robots_disallowed) > 15:
            lines.append(f"  ... and {len(r.robots_disallowed) - 15} more")
        lines.append("")

    if r.sitemap_url:
        lines.append(f"[Sitemap] {r.sitemap_url}")

    # security.txt
    if r.security_contact:
        lines.append(f"[security.txt] Contact: {r.security_contact}")

    # Sensitive paths
    if r.sensitive_paths:
        lines.append("")
        lines.append(f"[!] Sensitive Paths ({len(r.sensitive_paths)}):")
        for p in r.sensitive_paths:
            lines.append(f"  {p}")

    # Summary
    lines.append("")
    lines.append(f"Total endpoints discovered: {r.total_endpoints_discovered}")

    return "\n".join(lines)


@mcp.tool(
    name="ghost_api",
    description=(
        "Discover published API surfaces by probing well-known paths. "
        "Finds OpenAPI/Swagger docs, GraphQL endpoints (with introspection), "
        "OIDC/OAuth configuration, robots.txt, security.txt, CORS policy, "
        "API versioning, and framework fingerprinting. Completely passive "
        "Tier 1 — only accesses paths that legitimate clients would request."
    ),
    parameters={
        "url": {
            "type": "string",
            "description": "Base URL of the target to discover (e.g. https://api.example.com).",
        },
    },
)
async def ghost_api(url: str) -> str:
    """Discover published API surfaces for a target URL."""
    if not url:
        return "Error: url is required."
    report = await api_discover(url)
    return _format_api_discovery_report(report)


# ---------------------------------------------------------------------------
# Ephemeral authentication session tool
# ---------------------------------------------------------------------------

from .auth import get_session_manager, form_login


@mcp.tool(
    name="ghost_auth_session",
    description=(
        "Create or manage an ephemeral authentication session. Sessions are memory-only, "
        "auto-expire, and origin-locked. Use 'create' to start a session, 'list' to see "
        "active sessions, 'destroy' to end one."
    ),
    parameters={
        "action": {
            "type": "string",
            "description": "Action: create, list, destroy, destroy_all.",
            "default": "list",
        },
        "auth_type": {
            "type": "string",
            "description": "For create: bearer, cookie, basic, form.",
            "default": "bearer",
        },
        "origin": {
            "type": "string",
            "description": "For create: origin to lock session to (e.g., https://localhost:3000).",
            "default": "",
        },
        "token": {
            "type": "string",
            "description": "For create/bearer: the bearer token.",
            "default": "",
        },
        "cookies": {
            "type": "string",
            "description": "For create/cookie: JSON string of cookie name:value pairs.",
            "default": "",
        },
        "headers": {
            "type": "string",
            "description": "For create: JSON string of custom auth headers.",
            "default": "",
        },
        "ttl_minutes": {
            "type": "integer",
            "description": "Session lifetime in minutes (default 30, max 120).",
            "default": 30,
        },
        "session_id": {
            "type": "string",
            "description": "For destroy: session ID to destroy.",
            "default": "",
        },
        "url": {
            "type": "string",
            "description": "For create/form: login page URL.",
            "default": "",
        },
        "username": {
            "type": "string",
            "description": "For create/form: username.",
            "default": "",
        },
        "password": {
            "type": "string",
            "description": "For create/form: password.",
            "default": "",
        },
    },
)
async def ghost_auth_session(
    action: str = "list",
    auth_type: str = "bearer",
    origin: str = "",
    token: str = "",
    cookies: str = "",
    headers: str = "",
    ttl_minutes: int = 30,
    session_id: str = "",
    url: str = "",
    username: str = "",
    password: str = "",
) -> str:
    """Create or manage ephemeral authentication sessions."""
    mgr = get_session_manager()
    action = action.strip().lower()

    if action == "list":
        sessions = await mgr.list_sessions()
        if not sessions:
            return "No active auth sessions."
        lines = ["Active Auth Sessions", "=" * 40, ""]
        for s in sessions:
            lines.append(f"  ID: {s['session_id']}")
            lines.append(f"    Type:      {s['auth_type']}")
            lines.append(f"    Origin:    {s['origin']}")
            lines.append(f"    TTL:       {s['ttl_minutes']} min")
            lines.append(f"    Remaining: {s['remaining_seconds']}s")
            lines.append("")
        return "\n".join(lines)

    elif action == "create":
        if not origin:
            return "Error: origin is required for create (e.g., https://localhost:3000)."

        auth_type = auth_type.strip().lower()

        if auth_type == "form":
            # Form-based login via Playwright
            if not url:
                return "Error: url is required for form login."
            if not username or not password:
                return "Error: username and password are required for form login."

            result = await form_login(url=url, username=username, password=password)

            if not result.success:
                return f"Form login failed: {result.error or 'Unknown error'}"

            # Create session from captured cookies
            session = await mgr.create_session(
                auth_type="form",
                origin=origin,
                ttl_minutes=ttl_minutes,
                cookies=result.cookies,
            )

            cookie_count = len(result.cookies)
            storage_count = len(result.session_storage) if result.session_storage else 0
            return (
                f"Form login successful.\n"
                f"  Session ID:     {session.session_id}\n"
                f"  Origin:         {session.origin}\n"
                f"  TTL:            {session.ttl_minutes} min\n"
                f"  Cookies:        {cookie_count} captured\n"
                f"  Storage tokens: {storage_count} captured\n"
                f"  Final URL:      {result.final_url}"
            )

        elif auth_type == "bearer":
            if not token:
                return "Error: token is required for bearer auth."

            session = await mgr.create_session(
                auth_type="bearer",
                origin=origin,
                ttl_minutes=ttl_minutes,
                bearer_token=token,
            )
            return (
                f"Bearer auth session created.\n"
                f"  Session ID: {session.session_id}\n"
                f"  Origin:     {session.origin}\n"
                f"  TTL:        {session.ttl_minutes} min"
            )

        elif auth_type == "cookie":
            if not cookies:
                return "Error: cookies JSON string is required for cookie auth."

            try:
                cookie_dict = json.loads(cookies)
            except json.JSONDecodeError as e:
                return f"Error: invalid cookies JSON: {e}"

            if not isinstance(cookie_dict, dict):
                return "Error: cookies must be a JSON object (name: value pairs)."

            session = await mgr.create_session(
                auth_type="cookie",
                origin=origin,
                ttl_minutes=ttl_minutes,
                cookies=cookie_dict,
            )
            return (
                f"Cookie auth session created.\n"
                f"  Session ID: {session.session_id}\n"
                f"  Origin:     {session.origin}\n"
                f"  TTL:        {session.ttl_minutes} min\n"
                f"  Cookies:    {len(cookie_dict)} stored"
            )

        elif auth_type == "basic":
            # Basic auth stored as Authorization header
            if not username or not password:
                return "Error: username and password are required for basic auth."

            import base64
            credentials = base64.b64encode(f"{username}:{password}".encode()).decode()
            auth_headers = {"Authorization": f"Basic {credentials}"}

            # Parse any additional headers
            extra_headers = {}
            if headers:
                try:
                    extra_headers = json.loads(headers)
                except json.JSONDecodeError as e:
                    return f"Error: invalid headers JSON: {e}"
            auth_headers.update(extra_headers)

            session = await mgr.create_session(
                auth_type="basic",
                origin=origin,
                ttl_minutes=ttl_minutes,
                headers=auth_headers,
            )
            return (
                f"Basic auth session created.\n"
                f"  Session ID: {session.session_id}\n"
                f"  Origin:     {session.origin}\n"
                f"  TTL:        {session.ttl_minutes} min"
            )

        else:
            return f"Error: unknown auth_type '{auth_type}'. Use: bearer, cookie, basic, form."

    elif action == "destroy":
        if not session_id:
            return "Error: session_id is required for destroy."
        destroyed = await mgr.destroy_session(session_id)
        if destroyed:
            return f"Session {session_id} destroyed. Credentials wiped from memory."
        return f"Session {session_id} not found (may have already expired)."

    elif action == "destroy_all":
        count = await mgr.destroy_all()
        return f"All sessions destroyed ({count} wiped from memory)."

    else:
        return f"Error: unknown action '{action}'. Use: create, list, destroy, destroy_all."


# ---------------------------------------------------------------------------
# HTTP health endpoint + entry point
# ---------------------------------------------------------------------------

_start_time = time.time()
GHOST_VERSION = "0.4.0"


async def _health_handler(request):
    """Simple health check — returns JSON."""
    from starlette.responses import JSONResponse

    uptime = int(time.time() - _start_time)
    tool_count = len(mcp._tools)

    # Check Playwright availability
    playwright_ok = False
    try:
        from playwright.async_api import async_playwright
        playwright_ok = True
    except ImportError:
        pass

    body = {
        "status": "healthy",
        "version": GHOST_VERSION,
        "git_commit": os.environ.get("GHOST_GIT_COMMIT", "unknown"),
        "git_branch": os.environ.get("GHOST_GIT_BRANCH", "unknown"),
        "build_time": os.environ.get("GHOST_BUILD_TIME", "unknown"),
        "tools": tool_count,
        "playwright": playwright_ok,
        "paranoia": os.environ.get("GHOST_PARANOIA", "cautious"),
        "uptime_seconds": uptime,
    }
    return JSONResponse(body)


def main() -> None:
    """Run GhostMCP as an MCP server (stdio) or HTTP/WS server."""
    mode = os.environ.get("GHOST_MODE", "stdio")

    if mode == "server":
        # HTTP server mode — SSE + WebSocket + health endpoint
        import uvicorn
        from starlette.applications import Starlette
        from starlette.routing import Route, WebSocketRoute
        from starlette.responses import JSONResponse
        from starlette.websockets import WebSocket

        # --- SSE Transport (for opencode "type": "remote" with /sse URL) ---
        _sse_clients: dict[str, asyncio.Queue] = {}

        async def sse_endpoint(request):
            """SSE endpoint — client connects here, gets a session_id, then POSTs to /mcp."""
            from starlette.responses import StreamingResponse
            import uuid

            session_id = str(uuid.uuid4())
            queue: asyncio.Queue = asyncio.Queue()
            _sse_clients[session_id] = queue

            async def event_stream():
                # First event: tell client where to POST messages
                yield f"event: endpoint\ndata: /mcp?session_id={session_id}\n\n"
                try:
                    while True:
                        data = await queue.get()
                        yield f"event: message\ndata: {data}\n\n"
                except asyncio.CancelledError:
                    pass
                finally:
                    _sse_clients.pop(session_id, None)

            return StreamingResponse(event_stream(), media_type="text/event-stream",
                                     headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

        async def mcp_post_endpoint(request):
            """Receive MCP JSON-RPC messages via POST, return response via SSE stream."""
            session_id = request.query_params.get("session_id")
            if not session_id or session_id not in _sse_clients:
                return JSONResponse({"error": "Invalid or missing session_id"}, status_code=400)

            body = await request.body()
            raw = body.decode("utf-8")

            try:
                message = json.loads(raw)
            except json.JSONDecodeError:
                error_resp = json.dumps({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error"}})
                await _sse_clients[session_id].put(error_resp)
                return JSONResponse({"status": "error"}, status_code=200)

            response = await mcp.handle_request(message)
            if response:
                await _sse_clients[session_id].put(json.dumps(response))

            return JSONResponse({"status": "ok"}, status_code= 202)

        # --- WebSocket Transport ---
        async def ws_endpoint(websocket: WebSocket):
            """WebSocket endpoint — bidirectional JSON-RPC."""
            await websocket.accept()
            try:
                while True:
                    raw = await websocket.receive_text()
                    try:
                        message = json.loads(raw)
                    except json.JSONDecodeError:
                        error_resp = json.dumps({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error"}})
                        await websocket.send_text(error_resp)
                        continue

                    response = await mcp.handle_request(message)
                    if response:
                        await websocket.send_text(json.dumps(response))
            except Exception:
                pass
            finally:
                try:
                    await websocket.close()
                except Exception:
                    pass

        # --- Local Connectivity Bridge ---
        async def bridge_endpoint(websocket: WebSocket):
            """Bridge WebSocket — dev machines connect here to register local ports."""
            await websocket.accept()
            client_id = None
            
            try:
                # Wait for registration message
                raw = await asyncio.wait_for(websocket.receive_text(), timeout=10)
                msg = json.loads(raw)
                
                if msg.get("type") != "register":
                    await websocket.send_text(json.dumps({"type": "error", "error": "Expected register message"}))
                    return
                
                client_id = msg.get("client_id", f"bridge-{id(websocket)}")
                ports = msg.get("ports", [])
                web_access = msg.get("allow_web_access", False)
                web_mode = msg.get("web_access_mode", "false")
                locality = msg.get("locality", {})
                
                # Auto-detect locality from client's source IP if not provided
                if not locality:
                    try:
                        client_host = websocket.client.host if websocket.client else None
                        if client_host:
                            locality = await _detect_locality(client_host)
                    except Exception:
                        pass
                
                # Register this bridge client
                _register_bridge(client_id, {
                    "ws": websocket,
                    "ports": ports,
                    "web_access": web_access,
                    "web_mode": web_mode,
                    "locality": locality,
                })
                
                locality_str = f", locality={locality.get('region', '?')}" if locality else ""
                web_str = f", web={web_mode}" if web_access else ""
                print(f"[GhostMCP] Bridge connected: {client_id} ports={ports}{web_str}{locality_str}")
                
                # Acknowledge
                await websocket.send_text(json.dumps({
                    "type": "registered",
                    "client_id": client_id,
                    "ports": ports,
                }))
                
                # Handle responses and re-registrations from the bridge
                while True:
                    raw = await websocket.receive_text()
                    msg = json.loads(raw)
                    msg_type = msg.get("type", "")
                    
                    if msg_type in ("response", "error"):
                        req_id = msg.get("id")
                        if req_id and req_id in _bridge_pending:
                            future = _bridge_pending.pop(req_id)
                            if not future.done():
                                future.set_result(msg)
                    elif msg_type == "register":
                        # Re-registration (config file changed)
                        ports = msg.get("ports", [])
                        web_access = msg.get("allow_web_access", False)
                        web_mode = msg.get("web_access_mode", "false")
                        locality = msg.get("locality", {})
                        _register_bridge(client_id, {
                            "ws": websocket,
                            "ports": ports,
                            "web_access": web_access,
                            "web_mode": web_mode,
                            "locality": locality,
                        })
                        print(f"[GhostMCP] Bridge re-registered: {client_id} ports={ports}")
                        await websocket.send_text(json.dumps({
                            "type": "registered",
                            "client_id": client_id,
                            "ports": ports,
                        }))
                    elif msg_type == "heartbeat":
                        await websocket.send_text(json.dumps({"type": "heartbeat_ack"}))
                        
            except Exception as e:
                print(f"[GhostMCP] Bridge disconnected: {client_id or 'unknown'} ({e})")
            finally:
                if client_id:
                    _unregister_bridge(client_id)
                try:
                    await websocket.close()
                except Exception:
                    pass

        # --- App with all routes ---
        app = Starlette(routes=[
            Route("/health", _health_handler, methods=["GET"]),
            Route("/sse", sse_endpoint, methods=["GET"]),
            Route("/mcp", mcp_post_endpoint, methods=["POST"]),
            WebSocketRoute("/ws", ws_endpoint),
            WebSocketRoute("/bridge", bridge_endpoint),
        ])

        port = int(os.environ.get("GHOST_PORT", "8080"))
        print(f"[GhostMCP] Starting server on port {port}")
        print(f"[GhostMCP]   Health:    http://0.0.0.0:{port}/health")
        print(f"[GhostMCP]   SSE:       http://0.0.0.0:{port}/sse")
        print(f"[GhostMCP]   WebSocket: ws://0.0.0.0:{port}/ws")
        print(f"[GhostMCP]   Bridge:    ws://0.0.0.0:{port}/bridge")
        print(f"[GhostMCP]   Tools:     {len(mcp._tools)}")
        uvicorn.run(app, host="0.0.0.0", port=port, log_level="info")
    else:
        # Default: stdio MCP server
        asyncio.run(mcp.run_stdio())


if __name__ == "__main__":
    main()
