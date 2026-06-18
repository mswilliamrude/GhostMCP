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
from .engines.duckduckgo import DuckDuckGoEngine
from .engines.google import GoogleEngine
from .engines.serper import SerperEngine
from .dorking.builder import build_dork, from_template
from .dorking.templates import get_template_names
from .proxy.manager import ProxyManager
from .proxy.fingerprint import get_headers
from .recon.certs import CertReport, inspect_cert
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
from .utils.config import ParanoiaLevel


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
                return self._response(req_id, {
                    "content": [{"type": "text", "text": str(result)}],
                })
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
            "description": "Engine: auto, serper, google, duckduckgo. Auto tries serper -> google -> duckduckgo.",
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

    if engine == "auto":
        engines_to_try = []

        serper = SerperEngine(proxy=proxy)
        if serper.available:
            engines_to_try.append(serper)

        engines_to_try.append(GoogleEngine(proxy=proxy, paranoia=paranoia))
        engines_to_try.append(DuckDuckGoEngine(proxy=proxy))

        last_error = None
        for eng in engines_to_try:
            try:
                results = await eng.search(query, num_results=num_results)
                if results:
                    header = f"[{eng.name}] Results for: {query}\n\n"
                    return header + _format_results(results)
            except SearchEngineError as e:
                last_error = e
                continue

        if last_error:
            return f"All engines failed. Last error: {last_error}"
        return "No results found across all engines."

    eng_map = {
        "serper": lambda: SerperEngine(proxy=proxy),
        "google": lambda: GoogleEngine(proxy=proxy, paranoia=paranoia),
        "duckduckgo": lambda: DuckDuckGoEngine(proxy=proxy),
    }

    if engine not in eng_map:
        return f"Unknown engine '{engine}'. Available: {', '.join(eng_map.keys())}"

    try:
        eng_instance = eng_map[engine]()
        results = await eng_instance.search(query, num_results=num_results)
        header = f"[{engine}] Results for: {query}\n\n"
        return header + _format_results(results)
    except SearchEngineError as e:
        return f"Engine error: {e}"


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

    return "\n".join(lines)


@mcp.tool(
    name="ghost_cert",
    description=(
        "Inspect the TLS certificate of a host. Connects to host:port, pulls the "
        "certificate, and reports subject, issuer, expiry, SANs, fingerprint, "
        "protocol, cipher suite, key type, chain, and self-signed/expired status."
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
    },
)
async def ghost_cert(
    host: str,
    port: int = 443,
) -> str:
    """Inspect the TLS certificate of a host."""
    if not host:
        return "Error: host is required."

    report = await inspect_cert(host, port=port)
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
        "unresolved template syntax."
    ),
    parameters={
        "url": {"type": "string", "description": "URL to render."},
        "wait": {"type": "integer", "description": "Milliseconds to wait for JS execution (default 5000).", "default": 5000},
        "execute": {"type": "string", "description": "Optional JavaScript to run after page loads."},
        "extract": {"type": "string", "description": "What to return: dom, console, errors, all (default all).", "default": "all"},
        "screenshot": {"type": "boolean", "description": "Take a screenshot (saved to /tmp).", "default": False},
    },
)
async def ghost_render(
    url: str,
    wait: int = 5000,
    execute: Optional[str] = None,
    extract: str = "all",
    screenshot: bool = False,
) -> str:
    """Render a page with headless browser and capture console output."""
    
    # For localhost URLs with a bridge connected, fetch via bridge first
    # then render the HTML content with Playwright locally
    if _should_use_bridge(url):
        bridge_resp = await _fetch_via_bridge(url)
        if "error" in bridge_resp:
            return f"Bridge error: {bridge_resp['error']}"
        
        # Got the HTML via bridge — now render it with Playwright
        # using a data: URL so Playwright executes the JS locally
        html_content = bridge_resp.get("body", "")
        if not html_content:
            return f"Bridge returned empty response for {url}"
        
        # Render the bridged HTML through Playwright
        from .recon.render import render_page as _render
        import base64
        data_url = "data:text/html;base64," + base64.b64encode(html_content.encode()).decode()
        report = await _render(
            url=data_url,
            wait_ms=wait,
            execute_js=execute,
            capture_screenshot=screenshot,
        )
        # Override the URL in the report for clarity
        report.url = url
        report.final_url = url + " (via bridge)"
    else:
        report = await render_page(
            url=url,
            wait_ms=wait,
            execute_js=execute,
            capture_screenshot=screenshot,
        )

    if report.error:
        return f"Render error: {report.error}"

    lines = []

    if extract in ("all", "dom"):
        lines.append(f"=== Rendered Page: {report.title} ===")
        lines.append(f"URL: {report.final_url or report.url}")
        lines.append(f"Status: {report.status_code}")
        lines.append(f"Load time: {report.load_time_ms}ms")
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

    if report.screenshot_path and screenshot:
        lines.append(f"\nScreenshot saved: {report.screenshot_path}")

    return "\n".join(lines) if lines else "Page rendered successfully but no content extracted."


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
    report = await people_search(
        query_type=query_type,
        first=first, last=last, phone=phone, email=email,
        username=username, street=street, city=city, state=state,
    )
    return _format_people_report(report)


def _format_email_report(r: EmailReport) -> str:
    if r.error:
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
