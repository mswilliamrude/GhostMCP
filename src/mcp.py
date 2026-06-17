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
from typing import Any, Callable, Optional

import httpx

from .engines.base import SearchResult, SearchEngineError
from .engines.duckduckgo import DuckDuckGoEngine
from .engines.google import GoogleEngine
from .engines.serper import SerperEngine
from .dorking.builder import build_dork, from_template
from .dorking.templates import get_template_names
from .proxy.manager import ProxyManager
from .proxy.fingerprint import get_headers
from .recon.hashes import HashLookup, detect_hash_type, HashReport
from .recon.subdomains import enumerate_subdomains, SubdomainReport
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
        "Enumerate subdomains for a domain using Certificate Transparency logs (crt.sh). "
        "Returns deduplicated, sorted list of subdomains found in issued certificates."
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
    },
)
async def ghost_subdomains(
    domain: str,
    include_expired: bool = False,
) -> str:
    """Enumerate subdomains via Certificate Transparency logs."""
    if not domain:
        return "Error: domain is required."

    report = await enumerate_subdomains(domain, include_expired=include_expired)
    return _format_subdomain_report(report)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    """Run GhostMCP as an MCP server (stdio transport)."""
    asyncio.run(mcp.run_stdio())


if __name__ == "__main__":
    main()
