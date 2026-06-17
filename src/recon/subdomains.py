"""Subdomain enumeration via Certificate Transparency (crt.sh)."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone

import httpx

CRTSH_TIMEOUT = 15.0


@dataclass
class CertEntry:
    """A single certificate entry from crt.sh."""
    subdomain: str
    issuer: str
    not_before: str
    not_after: str

    @property
    def is_expired(self) -> bool:
        """Check if the certificate has expired."""
        try:
            expiry = datetime.fromisoformat(self.not_after.replace("T", " ").split(".")[0])
            return expiry < datetime.now(tz=None)
        except (ValueError, AttributeError):
            return False


@dataclass
class SubdomainReport:
    """Results of subdomain enumeration for a domain."""
    domain: str
    subdomains: list[str] = field(default_factory=list)
    cert_entries: list[CertEntry] = field(default_factory=list)
    total_certs: int = 0
    error: str | None = None


def _clean_subdomain(name: str) -> str | None:
    """Clean a subdomain name: strip wildcards, lowercase, validate."""
    name = name.strip().lower()
    # Strip wildcard prefix
    if name.startswith("*."):
        name = name[2:]
    # Basic validation — must contain at least one dot and only valid chars
    if not name or "." not in name:
        return None
    if not re.match(r"^[a-z0-9]([a-z0-9\-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]*[a-z0-9])?)*$", name):
        return None
    return name


def _parse_crtsh_response(
    data: list[dict],
    domain: str,
    include_expired: bool = False,
) -> SubdomainReport:
    """Parse crt.sh JSON response into a SubdomainReport."""
    report = SubdomainReport(domain=domain, total_certs=len(data))
    seen_subs: set[str] = set()
    entries: list[CertEntry] = []

    for entry in data:
        # name_value can contain multiple subdomains separated by newlines
        name_value = entry.get("name_value", "")
        issuer = entry.get("issuer_name", "")
        not_before = entry.get("not_before", "")
        not_after = entry.get("not_after", "")

        names = name_value.split("\n")
        for raw_name in names:
            cleaned = _clean_subdomain(raw_name)
            if cleaned is None:
                continue
            # Must belong to the target domain
            if not cleaned.endswith(f".{domain}") and cleaned != domain:
                continue

            cert_entry = CertEntry(
                subdomain=cleaned,
                issuer=issuer,
                not_before=not_before,
                not_after=not_after,
            )

            if not include_expired and cert_entry.is_expired:
                continue

            entries.append(cert_entry)
            seen_subs.add(cleaned)

    report.subdomains = sorted(seen_subs)
    report.cert_entries = entries
    return report


async def enumerate_subdomains(
    domain: str,
    include_expired: bool = False,
    timeout: float = CRTSH_TIMEOUT,
) -> SubdomainReport:
    """Query crt.sh Certificate Transparency logs for subdomains.

    Args:
        domain: Target domain (e.g. "example.com").
        include_expired: Include certificates past their not_after date.
        timeout: HTTP request timeout in seconds.

    Returns:
        SubdomainReport with deduplicated, sorted subdomain list.
    """
    domain = domain.strip().lower()
    url = f"https://crt.sh/?q=%.{domain}&output=json"

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.get(url)
            resp.raise_for_status()
            data = resp.json()
    except httpx.TimeoutException:
        return SubdomainReport(domain=domain, error=f"Timeout querying crt.sh for {domain}")
    except httpx.HTTPStatusError as e:
        return SubdomainReport(domain=domain, error=f"HTTP {e.response.status_code} from crt.sh")
    except httpx.RequestError as e:
        return SubdomainReport(domain=domain, error=f"Request failed: {e}")
    except Exception as e:
        return SubdomainReport(domain=domain, error=f"Unexpected error: {e}")

    return _parse_crtsh_response(data, domain, include_expired=include_expired)
