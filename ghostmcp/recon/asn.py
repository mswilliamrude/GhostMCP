"""BGP/ASN network infrastructure reconnaissance module.

Performs ASN lookups, prefix enumeration, peering discovery, and IX presence
mapping using free public APIs (BGPView primary, RIPEstat fallback).
"""

from __future__ import annotations

import asyncio
import re
import socket
from dataclasses import dataclass, field

import httpx

TIMEOUT = 12.0
BGPVIEW_BASE = "https://api.bgpview.io"
RIPESTAT_BASE = "https://stat.ripe.net/data"
USER_AGENT = "GhostMCP/0.5"


@dataclass
class ASNReport:
    """Result of a BGP/ASN infrastructure lookup."""

    query: str
    query_type: str = ""  # "asn", "ip", "org"

    # ASN info
    asn: int = 0
    asn_name: str = ""
    description: str = ""
    country: str = ""
    country_code: str = ""
    rir: str = ""  # ARIN, RIPE, APNIC, etc.
    allocation_date: str = ""

    # Prefixes
    prefixes_v4: list[dict] = field(default_factory=list)
    prefixes_v6: list[dict] = field(default_factory=list)
    prefix_count_v4: int = 0
    prefix_count_v6: int = 0

    # Peers
    upstream_peers: list[dict] = field(default_factory=list)
    downstream_peers: list[dict] = field(default_factory=list)

    # IX presence
    ix_presence: list[dict] = field(default_factory=list)

    # Related
    related_asns: list[dict] = field(default_factory=list)

    # Contact
    abuse_contact: str = ""

    # Investigation URLs
    investigation_urls: dict[str, str] = field(default_factory=dict)

    error: str | None = None


# ---------------------------------------------------------------------------
# Query-type detection
# ---------------------------------------------------------------------------

_ASN_RE = re.compile(r"^[Aa][Ss]?\d+$")


def _is_valid_ip(ip: str) -> bool:
    """Check if string is a valid IPv4 or IPv6 address."""
    for family in (socket.AF_INET, socket.AF_INET6):
        try:
            socket.inet_pton(family, ip.strip())
            return True
        except (socket.error, OSError):
            continue
    return False


def detect_query_type(query: str) -> str:
    """Auto-detect whether *query* is an ASN, IP, or organisation name.

    Returns one of ``"asn"``, ``"ip"``, or ``"org"``.
    """
    q = query.strip()
    if not q:
        return ""

    # Pure digits or "AS12345" / "as12345"
    if q.isdigit() or _ASN_RE.match(q):
        return "asn"

    # IP address (v4 or v6)
    if _is_valid_ip(q):
        return "ip"

    # Fallback: organisation name search
    return "org"


def _parse_asn_number(raw: str) -> int:
    """Strip ``AS`` / ``as`` prefix and return the integer ASN number.

    Raises ``ValueError`` if the result is not a positive integer.
    """
    cleaned = re.sub(r"^[Aa][Ss]", "", raw.strip())
    num = int(cleaned)
    if num <= 0:
        raise ValueError(f"ASN must be positive, got {num}")
    return num


# ---------------------------------------------------------------------------
# Investigation URL generation
# ---------------------------------------------------------------------------

def _generate_investigation_urls(asn: int) -> dict[str, str]:
    """Generate URLs for manual ASN investigation."""
    return {
        "bgpview": f"https://bgpview.io/asn/{asn}",
        "ripestat": f"https://stat.ripe.net/AS{asn}",
        "he_bgp": f"https://bgp.he.net/AS{asn}",
        "peeringdb": f"https://www.peeringdb.com/asn/{asn}",
        "bgp_tools": f"https://bgp.tools/as/{asn}",
    }


# ---------------------------------------------------------------------------
# BGPView API helpers — each takes a shared httpx.AsyncClient
# ---------------------------------------------------------------------------

async def _bgpview_get(client: httpx.AsyncClient, path: str) -> dict | None:
    """GET a BGPView endpoint; returns parsed JSON data or None on failure."""
    url = f"{BGPVIEW_BASE}{path}"
    try:
        resp = await client.get(url)
        if resp.status_code == 200:
            body = resp.json()
            if body.get("status") == "ok":
                return body.get("data")
        return None
    except (httpx.TimeoutException, httpx.ConnectError, Exception):
        return None


async def _ip_to_asn(ip: str, client: httpx.AsyncClient) -> int:
    """Resolve an IP to its origin ASN via BGPView ``/ip/{ip}``.

    Returns 0 if the lookup fails.
    """
    data = await _bgpview_get(client, f"/ip/{ip}")
    if not data:
        return 0

    # BGPView nests prefixes; grab the first ASN from the first prefix
    prefixes = data.get("prefixes", [])
    if not prefixes:
        return 0

    asn_info = prefixes[0].get("asn", {})
    return int(asn_info.get("asn", 0))


async def _search_org(name: str, client: httpx.AsyncClient) -> int:
    """Search BGPView for an organisation name; return the first matching ASN.

    Returns 0 if the search fails or yields no results.
    """
    url = f"{BGPVIEW_BASE}/search"
    try:
        resp = await client.get(url, params={"query_term": name})
        if resp.status_code != 200:
            return 0
        body = resp.json()
        if body.get("status") != "ok":
            return 0
        data = body.get("data", {})
        asns = data.get("asns", [])
        if asns:
            return int(asns[0].get("asn", 0))
        return 0
    except (httpx.TimeoutException, httpx.ConnectError, Exception):
        return 0


async def _fetch_asn_details(asn: int, client: httpx.AsyncClient) -> dict | None:
    """Fetch ASN overview from BGPView ``/asn/{asn}``."""
    return await _bgpview_get(client, f"/asn/{asn}")


async def _fetch_asn_prefixes(asn: int, client: httpx.AsyncClient) -> dict | None:
    """Fetch announced prefixes from BGPView ``/asn/{asn}/prefixes``."""
    return await _bgpview_get(client, f"/asn/{asn}/prefixes")


async def _fetch_asn_peers(asn: int, client: httpx.AsyncClient) -> dict | None:
    """Fetch upstream/downstream peers from BGPView ``/asn/{asn}/peers``."""
    return await _bgpview_get(client, f"/asn/{asn}/peers")


async def _fetch_asn_ixs(asn: int, client: httpx.AsyncClient) -> dict | None:
    """Fetch IX presence from BGPView ``/asn/{asn}/ixs``."""
    return await _bgpview_get(client, f"/asn/{asn}/ixs")


# ---------------------------------------------------------------------------
# Response parsers — populate report fields from API data dicts
# ---------------------------------------------------------------------------

def _parse_details(report: ASNReport, data: dict | None) -> None:
    """Populate core ASN fields from the ``/asn/{asn}`` response."""
    if not data:
        return
    report.asn_name = data.get("name", "")
    report.description = data.get("description_short", "") or data.get("description_full", "")
    report.country_code = data.get("country_code", "")

    rir_alloc = data.get("rir_allocation") or {}
    report.rir = rir_alloc.get("rir_name", "")
    report.allocation_date = rir_alloc.get("date_allocated", "")

    # Abuse contact — first email_contacts entry
    emails = data.get("email_contacts") or []
    if emails:
        report.abuse_contact = emails[0]


def _parse_prefixes(report: ASNReport, data: dict | None) -> None:
    """Populate prefix lists from the ``/asn/{asn}/prefixes`` response."""
    if not data:
        return

    for p in data.get("ipv4_prefixes", []):
        report.prefixes_v4.append({
            "prefix": p.get("prefix", ""),
            "name": p.get("name", ""),
            "description": p.get("description", ""),
            "country": p.get("country_code", ""),
        })

    for p in data.get("ipv6_prefixes", []):
        report.prefixes_v6.append({
            "prefix": p.get("prefix", ""),
            "name": p.get("name", ""),
            "description": p.get("description", ""),
            "country": p.get("country_code", ""),
        })

    report.prefix_count_v4 = len(report.prefixes_v4)
    report.prefix_count_v6 = len(report.prefixes_v6)


def _parse_peers(report: ASNReport, data: dict | None) -> None:
    """Populate upstream/downstream peer lists from ``/asn/{asn}/peers``."""
    if not data:
        return

    for p in data.get("ipv4_peers", []):
        entry = {
            "asn": p.get("asn", 0),
            "name": p.get("name", ""),
            "description": p.get("description", ""),
            "country": p.get("country_code", ""),
        }
        if p.get("is_upstream"):
            report.upstream_peers.append(entry)
        else:
            report.downstream_peers.append(entry)

    for p in data.get("ipv6_peers", []):
        entry = {
            "asn": p.get("asn", 0),
            "name": p.get("name", ""),
            "description": p.get("description", ""),
            "country": p.get("country_code", ""),
        }
        if p.get("is_upstream"):
            if not any(e["asn"] == entry["asn"] for e in report.upstream_peers):
                report.upstream_peers.append(entry)
        else:
            if not any(e["asn"] == entry["asn"] for e in report.downstream_peers):
                report.downstream_peers.append(entry)


def _parse_ixs(report: ASNReport, data: dict | None) -> None:
    """Populate IX presence from ``/asn/{asn}/ixs``."""
    if not data:
        return

    for ix in data if isinstance(data, list) else []:
        report.ix_presence.append({
            "name": ix.get("name", ""),
            "full_name": ix.get("name_full", ""),
            "city": ix.get("city", ""),
            "country": ix.get("country_code", ""),
            "speed": ix.get("speed", 0),
        })


# ---------------------------------------------------------------------------
# Main lookup
# ---------------------------------------------------------------------------

async def asn_lookup(query: str, query_type: str = "") -> ASNReport:
    """Look up ASN/BGP infrastructure for an ASN number, IP, or organisation.

    Args:
        query:      ASN number (``"15169"`` or ``"AS15169"``), IP address, or
                    organisation name.
        query_type: ``"asn"``, ``"ip"``, or ``"org"``.  Auto-detected when
                    empty.

    Returns:
        Populated ``ASNReport`` dataclass.
    """
    query = (query or "").strip()
    if not query:
        return ASNReport(query="", error="Query is required.")

    # Auto-detect query type
    if not query_type:
        query_type = detect_query_type(query)
    query_type = query_type.strip().lower()

    report = ASNReport(query=query, query_type=query_type)

    async with httpx.AsyncClient(
        timeout=TIMEOUT,
        headers={"User-Agent": USER_AGENT},
    ) as client:
        # ----- Resolve to an ASN number -----
        asn_num = 0

        if query_type == "asn":
            try:
                asn_num = _parse_asn_number(query)
            except (ValueError, TypeError) as exc:
                report.error = f"Invalid ASN: {exc}"
                return report

        elif query_type == "ip":
            asn_num = await _ip_to_asn(query, client)
            if not asn_num:
                report.error = f"Could not resolve IP {query} to an ASN."
                return report

        elif query_type == "org":
            asn_num = await _search_org(query, client)
            if not asn_num:
                report.error = f"No ASN found for organisation: {query}"
                return report
        else:
            report.error = f"Unknown query_type: {query_type}"
            return report

        report.asn = asn_num

        # ----- Parallel fetch all BGPView data for the ASN -----
        details, prefixes, peers, ixs = await asyncio.gather(
            _fetch_asn_details(asn_num, client),
            _fetch_asn_prefixes(asn_num, client),
            _fetch_asn_peers(asn_num, client),
            _fetch_asn_ixs(asn_num, client),
        )

    # ----- Parse responses (individual failures → partial data) -----
    _parse_details(report, details)
    _parse_prefixes(report, prefixes)
    _parse_peers(report, peers)
    _parse_ixs(report, ixs)

    # Detect total API failure (all endpoints returned None)
    if all(x is None for x in (details, prefixes, peers, ixs)):
        report.error = (
            f"BGPView API unreachable for AS{asn_num} "
            f"(DNS resolution or connectivity failure). "
            f"Investigation URLs provided for manual lookup."
        )

    # Country from details or fallback
    if report.country_code and not report.country:
        report.country = report.country_code

    # Investigation URLs (always populated, even on API failure)
    report.investigation_urls = _generate_investigation_urls(asn_num)

    return report
