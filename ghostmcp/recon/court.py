"""Court record search module — query CourtListener and generate legal OSINT URLs."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from urllib.parse import quote, quote_plus

import httpx

TIMEOUT = 15.0

# CourtListener REST API v4
COURTLISTENER_BASE = "https://www.courtlistener.com/api/rest/v4"
COURTLISTENER_SEARCH = f"{COURTLISTENER_BASE}/search/"


@dataclass
class CourtCase:
    case_name: str = ""
    docket_number: str = ""
    court: str = ""
    date_filed: str = ""
    date_terminated: str = ""
    parties: list[str] = field(default_factory=list)
    attorneys: list[str] = field(default_factory=list)
    nature_of_suit: str = ""
    source_url: str = ""


@dataclass
class CourtSearchResult:
    query: str
    total_results: int = 0
    cases: list[CourtCase] = field(default_factory=list)
    search_urls: dict = field(default_factory=dict)
    error: str | None = None


# ---------------------------------------------------------------------------
# Search URL generation
# ---------------------------------------------------------------------------

def _build_search_urls(query: str) -> dict[str, str]:
    """Generate OSINT search URLs for court/legal record lookups."""
    encoded = quote_plus(query)
    quoted = quote(f'"{query}"', safe="")

    urls: dict[str, str] = {
        "courtlistener": f"https://www.courtlistener.com/?q={encoded}&type=r",
        "judyrecords": f"https://www.judyrecords.com/record?q={quoted}",
        "pacer": "https://pcl.uscourts.gov/pcl/pages/search.jsf",
    }

    # NSOPW — try to split into first/last name for the search form
    parts = query.strip().split()
    if len(parts) >= 2:
        first = quote_plus(parts[0])
        last = quote_plus(parts[-1])
        urls["nsopw"] = (
            f"https://www.nsopw.gov/search-public"
            f"?FirstName={first}&LastName={last}"
        )
    else:
        urls["nsopw"] = (
            f"https://www.nsopw.gov/search-public?LastName={encoded}"
        )

    return urls


# ---------------------------------------------------------------------------
# CourtListener API
# ---------------------------------------------------------------------------

def _parse_case(item: dict) -> CourtCase:
    """Parse a single CourtListener search result into a CourtCase."""
    # CourtListener search results vary in shape depending on type=r vs type=o.
    # For RECAP dockets (type=r), fields appear at the top level.
    case_name = (
        item.get("caseName", "")
        or item.get("case_name", "")
        or item.get("caseNameFull", "")
        or ""
    )
    docket_number = item.get("docketNumber", "") or item.get("docket_number", "") or ""
    court = item.get("court", "") or item.get("court_citation_string", "") or ""
    date_filed = item.get("dateFiled", "") or item.get("date_filed", "") or ""
    date_terminated = (
        item.get("dateTerminated", "")
        or item.get("date_terminated", "")
        or ""
    )
    nature_of_suit = item.get("suitNature", "") or item.get("nature_of_suit", "") or ""

    # Parties — may be a string or list depending on endpoint
    raw_parties = item.get("party", [])
    if isinstance(raw_parties, str):
        parties = [p.strip() for p in raw_parties.split(";") if p.strip()]
    elif isinstance(raw_parties, list):
        parties = [str(p) for p in raw_parties if p]
    else:
        parties = []

    # Attorneys
    raw_attorneys = item.get("attorney", [])
    if isinstance(raw_attorneys, str):
        attorneys = [a.strip() for a in raw_attorneys.split(";") if a.strip()]
    elif isinstance(raw_attorneys, list):
        attorneys = [str(a) for a in raw_attorneys if a]
    else:
        attorneys = []

    # Source URL
    absolute_url = item.get("absolute_url", "")
    if absolute_url:
        source_url = f"https://www.courtlistener.com{absolute_url}"
    else:
        docket_id = item.get("docket_id", "") or item.get("id", "")
        source_url = (
            f"https://www.courtlistener.com/docket/{docket_id}/"
            if docket_id
            else ""
        )

    return CourtCase(
        case_name=case_name,
        docket_number=docket_number,
        court=court,
        date_filed=date_filed,
        date_terminated=date_terminated,
        parties=parties,
        attorneys=attorneys,
        nature_of_suit=nature_of_suit,
        source_url=source_url,
    )


async def _query_courtlistener(
    client: httpx.AsyncClient,
    query: str,
    search_type: str,
) -> tuple[int, list[CourtCase], str | None]:
    """Query CourtListener search API.

    Returns (total_results, cases, error_or_none).
    """
    token = os.environ.get("GHOST_COURTLISTENER_TOKEN", "")
    if not token:
        return 0, [], "GHOST_COURTLISTENER_TOKEN not set — returning search URLs only"

    headers = {
        "Authorization": f"Token {token}",
    }

    params: dict[str, str] = {
        "q": query,
        "type": "r",  # RECAP / dockets
    }

    # For docket number searches, use a more targeted query
    if search_type == "docket":
        params["q"] = f'docketNumber:"{query}"'

    try:
        resp = await client.get(
            COURTLISTENER_SEARCH,
            params=params,
            headers=headers,
        )
        if resp.status_code == 200:
            data = resp.json()
            total = data.get("count", 0)
            results = data.get("results", [])
            cases = [_parse_case(item) for item in results]
            return total, cases, None
        elif resp.status_code == 401:
            return 0, [], "Invalid GHOST_COURTLISTENER_TOKEN"
        elif resp.status_code == 429:
            return 0, [], "CourtListener rate limit exceeded"
        else:
            return 0, [], f"HTTP {resp.status_code}"
    except (httpx.TimeoutException, httpx.ConnectError) as exc:
        return 0, [], str(exc)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

async def court_search(
    query: str,
    search_type: str = "party",
) -> CourtSearchResult:
    """Search court records via CourtListener API.

    Args:
        query: Party name or docket number to search for.
        search_type: "party" to search by name, "docket" to search by
            docket number.

    Returns:
        CourtSearchResult with matching cases and OSINT URLs.
        If GHOST_COURTLISTENER_TOKEN is not set, returns search URLs only.
    """
    query = query.strip()
    if not query:
        return CourtSearchResult(
            query=query,
            error="Empty query",
            search_urls=_build_search_urls(query),
        )

    result = CourtSearchResult(
        query=query,
        search_urls=_build_search_urls(query),
    )

    token = os.environ.get("GHOST_COURTLISTENER_TOKEN", "")
    if not token:
        result.error = "GHOST_COURTLISTENER_TOKEN not set — search URLs generated only"
        return result

    async with httpx.AsyncClient(timeout=TIMEOUT) as client:
        total, cases, error = await _query_courtlistener(client, query, search_type)

    result.total_results = total
    result.cases = cases
    if error:
        result.error = error

    return result
