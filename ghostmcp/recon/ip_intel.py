"""IP address intelligence module — geolocation, ASN, threat intel, and reverse DNS."""

from __future__ import annotations

import asyncio
import os
import socket
from dataclasses import dataclass, field

import httpx

TIMEOUT = 10.0

# ip-api.com — free, no key, 45 req/min, JSON batch supported
IP_API_URL = "http://ip-api.com/json/{ip}"
IP_API_BATCH_URL = "http://ip-api.com/batch"
IP_API_FIELDS = "status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,reverse,mobile,proxy,hosting,query"


@dataclass
class IPReport:
    """Result of an IP address intelligence lookup."""

    ip: str
    valid: bool = False

    # Geolocation
    country: str = ""
    country_code: str = ""
    region: str = ""
    region_name: str = ""
    city: str = ""
    zip_code: str = ""
    latitude: float | None = None
    longitude: float | None = None
    timezone: str = ""

    # Network
    isp: str = ""
    org: str = ""
    asn: str = ""
    as_name: str = ""
    reverse_dns: str = ""

    # Classification
    is_mobile: bool = False
    is_proxy: bool = False
    is_hosting: bool = False

    # Threat context (from GhostMCP ghost_threat if available)
    threat_hits: list[dict] = field(default_factory=list)

    # Search URLs
    search_urls: dict[str, str] = field(default_factory=dict)

    error: str | None = None


# ---------------------------------------------------------------------------
# IP validation
# ---------------------------------------------------------------------------

def _is_valid_ipv4(ip: str) -> bool:
    """Check if string is a valid IPv4 address."""
    parts = ip.strip().split(".")
    if len(parts) != 4:
        return False
    for part in parts:
        try:
            num = int(part)
            if num < 0 or num > 255:
                return False
        except ValueError:
            return False
    return True


def _is_valid_ipv6(ip: str) -> bool:
    """Check if string is a valid IPv6 address."""
    try:
        socket.inet_pton(socket.AF_INET6, ip.strip())
        return True
    except (socket.error, OSError):
        return False


def _is_valid_ip(ip: str) -> bool:
    """Check if string is a valid IP address (v4 or v6)."""
    return _is_valid_ipv4(ip) or _is_valid_ipv6(ip)


# ---------------------------------------------------------------------------
# ip-api.com lookup (free, no key, 45 req/min)
# ---------------------------------------------------------------------------

async def _query_ip_api(ip: str) -> dict | None:
    """Query ip-api.com for geolocation and network data.

    Free tier: 45 req/min, HTTP only (HTTPS requires paid).
    Returns full field set including proxy/hosting/mobile flags.
    """
    url = IP_API_URL.format(ip=ip) + f"?fields={IP_API_FIELDS}"
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            resp = await client.get(url)
            if resp.status_code == 200:
                data = resp.json()
                if data.get("status") == "success":
                    return data
                else:
                    return {"error": data.get("message", "Unknown error")}
            elif resp.status_code == 429:
                return {"error": "Rate limited (45 req/min exceeded)"}
            else:
                return {"error": f"HTTP {resp.status_code}"}
    except httpx.TimeoutException:
        return {"error": "Timeout connecting to ip-api.com"}
    except httpx.ConnectError:
        return {"error": "Connection failed to ip-api.com"}
    except Exception as e:
        return {"error": f"ip-api.com error: {e}"}


# ---------------------------------------------------------------------------
# Reverse DNS
# ---------------------------------------------------------------------------

async def _reverse_dns(ip: str) -> str:
    """Perform reverse DNS lookup."""
    try:
        result = await asyncio.to_thread(socket.gethostbyaddr, ip)
        return result[0] if result else ""
    except (socket.herror, socket.gaierror, OSError):
        return ""


# ---------------------------------------------------------------------------
# Search URL generation
# ---------------------------------------------------------------------------

def _generate_search_urls(ip: str) -> dict[str, str]:
    """Generate investigation URLs for an IP address."""
    return {
        "abuseipdb": f"https://www.abuseipdb.com/check/{ip}",
        "shodan": f"https://www.shodan.io/host/{ip}",
        "censys": f"https://search.censys.io/hosts/{ip}",
        "greynoise": f"https://viz.greynoise.io/ip/{ip}",
        "virustotal": f"https://www.virustotal.com/gui/ip-address/{ip}",
        "ipinfo": f"https://ipinfo.io/{ip}",
        "whois": f"https://who.is/whois-ip/ip-address/{ip}",
        "bgpview": f"https://bgpview.io/ip/{ip}",
        "threatcrowd": f"https://www.threatcrowd.org/ip.php?ip={ip}",
        "urlhaus": f"https://urlhaus.abuse.ch/browse.php?search={ip}",
    }


# ---------------------------------------------------------------------------
# Main lookup function
# ---------------------------------------------------------------------------

async def ip_lookup(ip: str) -> IPReport:
    """Look up an IP address: geolocation, ASN/ISP, reverse DNS, proxy detection.

    Uses ip-api.com (free, no key, 45 req/min).
    Generates search URLs for deeper investigation (Shodan, AbuseIPDB, etc.).

    Args:
        ip: IPv4 or IPv6 address to investigate.

    Returns:
        IPReport with geolocation, network, classification, and search URLs.
    """
    ip = ip.strip()

    if not ip:
        return IPReport(ip=ip, error="IP address is required.")

    if not _is_valid_ip(ip):
        return IPReport(ip=ip, error=f"Invalid IP address: {ip}")

    report = IPReport(ip=ip, valid=True)

    # Run ip-api.com + reverse DNS in parallel
    ip_api_task = _query_ip_api(ip)
    rdns_task = _reverse_dns(ip)
    ip_data, rdns = await asyncio.gather(ip_api_task, rdns_task)

    # Parse ip-api.com response
    if ip_data and "error" not in ip_data:
        report.country = ip_data.get("country", "")
        report.country_code = ip_data.get("countryCode", "")
        report.region = ip_data.get("region", "")
        report.region_name = ip_data.get("regionName", "")
        report.city = ip_data.get("city", "")
        report.zip_code = ip_data.get("zip", "")
        report.latitude = ip_data.get("lat")
        report.longitude = ip_data.get("lon")
        report.timezone = ip_data.get("timezone", "")
        report.isp = ip_data.get("isp", "")
        report.org = ip_data.get("org", "")
        report.asn = ip_data.get("as", "")
        report.as_name = ip_data.get("asname", "")
        report.is_mobile = ip_data.get("mobile", False)
        report.is_proxy = ip_data.get("proxy", False)
        report.is_hosting = ip_data.get("hosting", False)
        # ip-api also returns reverse DNS
        report.reverse_dns = ip_data.get("reverse", "") or rdns
    elif ip_data and "error" in ip_data:
        report.error = ip_data["error"]
    else:
        report.error = "No data returned from ip-api.com"

    # Fallback reverse DNS if ip-api didn't provide it
    if not report.reverse_dns and rdns:
        report.reverse_dns = rdns

    # Generate search URLs
    report.search_urls = _generate_search_urls(ip)

    return report
