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

import httpx

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
# HTTP health endpoint + entry point
# ---------------------------------------------------------------------------

_start_time = time.time()
GHOST_VERSION = "0.3.5"


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

        # --- App with all routes ---
        app = Starlette(routes=[
            Route("/health", _health_handler, methods=["GET"]),
            Route("/sse", sse_endpoint, methods=["GET"]),
            Route("/mcp", mcp_post_endpoint, methods=["POST"]),
            WebSocketRoute("/ws", ws_endpoint),
        ])

        port = int(os.environ.get("GHOST_PORT", "8080"))
        print(f"[GhostMCP] Starting server on port {port}")
        print(f"[GhostMCP]   Health:    http://0.0.0.0:{port}/health")
        print(f"[GhostMCP]   SSE:       http://0.0.0.0:{port}/sse")
        print(f"[GhostMCP]   WebSocket: ws://0.0.0.0:{port}/ws")
        print(f"[GhostMCP]   Tools:     {len(mcp._tools)}")
        uvicorn.run(app, host="0.0.0.0", port=port, log_level="info")
    else:
        # Default: stdio MCP server
        asyncio.run(mcp.run_stdio())


if __name__ == "__main__":
    main()
