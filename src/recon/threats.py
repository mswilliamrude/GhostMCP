"""Threat intelligence feeds module — query free TI sources for IOCs."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

import httpx

TIMEOUT = 10.0

# abuse.ch services
URLHAUS_URL_API = "https://urlhaus-api.abuse.ch/v1/url/"
URLHAUS_HOST_API = "https://urlhaus-api.abuse.ch/v1/host/"
THREATFOX_API = "https://threatfox-api.abuse.ch/api/v1/"
FEODO_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"

# RansomWatch
RANSOMWATCH_URL = "https://raw.githubusercontent.com/joshhighet/ransomwatch/main/posts.json"


def _detect_indicator_type(query: str) -> str:
    """Detect the type of indicator from a query string.

    Returns one of: url, ip, hash, domain.
    """
    q = query.strip()

    # URL
    if q.startswith(("http://", "https://")):
        return "url"

    # IPv4 (simple check)
    parts = q.split(".")
    if len(parts) == 4:
        try:
            if all(0 <= int(p) <= 255 for p in parts):
                return "ip"
        except ValueError:
            pass

    # IPv6 (contains colons, no dots or slash)
    if ":" in q and "/" not in q and "." not in q:
        return "ip"

    # Hash (hex string of standard lengths)
    if all(c in "0123456789abcdefABCDEF" for c in q) and len(q) in (32, 40, 64, 128):
        return "hash"

    # Default to domain
    return "domain"


@dataclass
class ThreatEntry:
    source: str  # "urlhaus", "threatfox", "malwarebazaar", "ransomwatch"
    indicator: str  # URL, hash, IP, domain
    indicator_type: str  # "url", "hash", "ip", "domain"
    threat_type: str  # "malware", "c2", "phishing", "ransomware"
    malware_family: str
    tags: list[str]
    first_seen: str
    reference: str  # source URL for provenance


@dataclass
class ThreatReport:
    query: str
    entries: list[ThreatEntry] = field(default_factory=list)
    sources_queried: list[str] = field(default_factory=list)
    errors: dict[str, str] = field(default_factory=dict)  # source -> error message


# ---------------------------------------------------------------------------
# URLhaus
# ---------------------------------------------------------------------------

async def query_urlhaus(query: str) -> list[ThreatEntry]:
    """Query URLhaus for malware distribution URLs.

    Detects whether the query is a URL or domain/IP and uses the
    appropriate API endpoint.
    """
    indicator_type = _detect_indicator_type(query)
    entries: list[ThreatEntry] = []

    if indicator_type == "url":
        url = URLHAUS_URL_API
        payload = {"url": query}
    else:
        url = URLHAUS_HOST_API
        payload = {"host": query}

    async with httpx.AsyncClient(timeout=TIMEOUT) as client:
        try:
            resp = await client.post(url, data=payload)
            if resp.status_code != 200:
                return entries
            data = resp.json()
        except (httpx.TimeoutException, httpx.ConnectError):
            return entries

    # Single URL lookup returns a flat object
    if indicator_type == "url":
        if data.get("query_status") == "ok":
            entries.append(ThreatEntry(
                source="urlhaus",
                indicator=data.get("url", query),
                indicator_type="url",
                threat_type=data.get("threat", "malware"),
                malware_family=data.get("tags", [""])[0] if data.get("tags") else "",
                tags=data.get("tags") or [],
                first_seen=data.get("date_added", ""),
                reference=data.get("urlhaus_reference", ""),
            ))
    else:
        # Host lookup returns a list of URLs
        urls = data.get("urls", [])
        for item in urls:
            entries.append(ThreatEntry(
                source="urlhaus",
                indicator=item.get("url", ""),
                indicator_type="url",
                threat_type=item.get("threat", "malware"),
                malware_family=item.get("tags", [""])[0] if item.get("tags") else "",
                tags=item.get("tags") or [],
                first_seen=item.get("date_added", ""),
                reference=item.get("urlhaus_reference", ""),
            ))

    return entries


# ---------------------------------------------------------------------------
# ThreatFox
# ---------------------------------------------------------------------------

async def query_threatfox_iocs(days: int = 7) -> list[ThreatEntry]:
    """Get recent IOCs from ThreatFox.

    Returns IOCs published in the last N days.
    """
    entries: list[ThreatEntry] = []
    payload = {"query": "get_iocs", "days": days}

    async with httpx.AsyncClient(timeout=TIMEOUT) as client:
        try:
            resp = await client.post(THREATFOX_API, json=payload)
            if resp.status_code != 200:
                return entries
            data = resp.json()
        except (httpx.TimeoutException, httpx.ConnectError):
            return entries

    if data.get("query_status") != "ok":
        return entries

    for item in data.get("data", []) or []:
        ioc_value = item.get("ioc", "")
        ioc_type_raw = item.get("ioc_type", "")

        # Map ThreatFox ioc_type to our types
        if "url" in ioc_type_raw.lower():
            ioc_type = "url"
        elif "ip" in ioc_type_raw.lower():
            ioc_type = "ip"
        elif "domain" in ioc_type_raw.lower():
            ioc_type = "domain"
        else:
            ioc_type = "hash"

        threat_type_raw = item.get("threat_type", "")
        if "botnet" in threat_type_raw.lower():
            threat_type = "c2"
        elif "payload" in threat_type_raw.lower():
            threat_type = "malware"
        else:
            threat_type = threat_type_raw or "malware"

        entries.append(ThreatEntry(
            source="threatfox",
            indicator=ioc_value,
            indicator_type=ioc_type,
            threat_type=threat_type,
            malware_family=item.get("malware_printable", ""),
            tags=item.get("tags") or [],
            first_seen=item.get("first_seen_utc", ""),
            reference=item.get("reference", ""),
        ))

    return entries


# ---------------------------------------------------------------------------
# RansomWatch
# ---------------------------------------------------------------------------

async def query_ransomwatch() -> list[ThreatEntry]:
    """Get recent ransomware victim postings from RansomWatch."""
    entries: list[ThreatEntry] = []

    async with httpx.AsyncClient(timeout=TIMEOUT) as client:
        try:
            resp = await client.get(RANSOMWATCH_URL)
            if resp.status_code != 200:
                return entries
            data = resp.json()
        except (httpx.TimeoutException, httpx.ConnectError):
            return entries

    if not isinstance(data, list):
        return entries

    for item in data:
        post_title = item.get("post_title", "")
        group_name = item.get("group_name", "")
        discovered = item.get("discovered", "")
        post_url = item.get("post_url", "")

        entries.append(ThreatEntry(
            source="ransomwatch",
            indicator=post_title,
            indicator_type="domain",
            threat_type="ransomware",
            malware_family=group_name,
            tags=[group_name] if group_name else [],
            first_seen=discovered,
            reference=post_url,
        ))

    return entries


# ---------------------------------------------------------------------------
# Feodo Tracker
# ---------------------------------------------------------------------------

async def query_feodo() -> list[ThreatEntry]:
    """Get Feodo Tracker botnet C2 list."""
    entries: list[ThreatEntry] = []

    async with httpx.AsyncClient(timeout=TIMEOUT) as client:
        try:
            resp = await client.get(FEODO_URL)
            if resp.status_code != 200:
                return entries
            data = resp.json()
        except (httpx.TimeoutException, httpx.ConnectError):
            return entries

    for item in data if isinstance(data, list) else []:
        entries.append(ThreatEntry(
            source="feodo",
            indicator=item.get("ip_address", ""),
            indicator_type="ip",
            threat_type="c2",
            malware_family=item.get("malware", ""),
            tags=[item.get("status", "")] if item.get("status") else [],
            first_seen=item.get("first_seen", ""),
            reference="https://feodotracker.abuse.ch",
        ))

    return entries


# ---------------------------------------------------------------------------
# Aggregated threat lookup
# ---------------------------------------------------------------------------

_SOURCE_FUNCTIONS = {
    "urlhaus": None,  # Needs query param — handled specially
    "threatfox": query_threatfox_iocs,
    "ransomwatch": query_ransomwatch,
    "feodo": query_feodo,
}

ALL_SOURCES = list(_SOURCE_FUNCTIONS.keys())


async def threat_lookup(
    query: str,
    sources: list[str] | None = None,
    days: int = 7,
) -> ThreatReport:
    """Query multiple threat intel sources for an indicator.

    Runs relevant queries in parallel based on indicator type and
    requested sources.
    """
    if sources is None:
        sources = ALL_SOURCES

    report = ThreatReport(query=query)

    async def _run_urlhaus() -> list[ThreatEntry]:
        return await query_urlhaus(query)

    async def _run_threatfox() -> list[ThreatEntry]:
        return await query_threatfox_iocs(days=days)

    async def _run_ransomwatch() -> list[ThreatEntry]:
        return await query_ransomwatch()

    async def _run_feodo() -> list[ThreatEntry]:
        return await query_feodo()

    dispatch = {
        "urlhaus": _run_urlhaus,
        "threatfox": _run_threatfox,
        "ransomwatch": _run_ransomwatch,
        "feodo": _run_feodo,
    }

    tasks: list[tuple[str, asyncio.Task]] = []
    for source in sources:
        source = source.strip().lower()
        if source in dispatch:
            report.sources_queried.append(source)
            task = asyncio.create_task(dispatch[source]())
            tasks.append((source, task))
        else:
            report.errors[source] = f"Unknown source: {source}"

    for source, task in tasks:
        try:
            entries = await task
            report.entries.extend(entries)
        except Exception as e:
            report.errors[source] = str(e)

    return report
