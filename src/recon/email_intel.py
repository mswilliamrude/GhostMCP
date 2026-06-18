"""Email intelligence module — reputation, breach, enrichment, and OSINT link generation."""

from __future__ import annotations

import asyncio
import os
import shlex
from dataclasses import dataclass, field
from urllib.parse import quote

import httpx

TIMEOUT = 10.0

FREE_PROVIDERS: set[str] = {
    "gmail.com",
    "yahoo.com",
    "hotmail.com",
    "outlook.com",
    "aol.com",
    "icloud.com",
    "protonmail.com",
    "proton.me",
    "mail.com",
    "yandex.com",
    "zoho.com",
    "gmx.com",
    "tutanota.com",
    "fastmail.com",
    "live.com",
    "msn.com",
}

# API endpoints
EMAILREP_URL = "https://emailrep.io"
HUNTER_URL = "https://api.hunter.io/v2/email-finder"
HIBP_URL = "https://haveibeenpwned.com/api/v3/breachedaccount"


@dataclass
class EmailReport:
    email: str
    valid: bool = False
    domain: str = ""
    is_free_provider: bool = False
    reputation: dict | None = None
    accounts_found: list[str] = field(default_factory=list)
    breach_count: int | None = None
    breaches: list[str] = field(default_factory=list)
    hunter_enrichment: dict | None = None
    search_urls: dict = field(default_factory=dict)
    errors: dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------

def _basic_validate(email: str) -> tuple[bool, str]:
    """Minimal email format check. Returns (valid, domain)."""
    email = email.strip().lower()
    if "@" not in email:
        return False, ""
    parts = email.rsplit("@", 1)
    if len(parts) != 2 or not parts[0] or not parts[1]:
        return False, ""
    local, domain = parts
    if "." not in domain:
        return False, ""
    return True, domain


def _build_search_urls(email: str) -> dict[str, str]:
    """Generate OSINT search URLs for an email address."""
    encoded = quote(email, safe="")
    return {
        "haveibeenpwned": f"https://haveibeenpwned.com/account/{encoded}",
        "emailrep": f"https://emailrep.io/{encoded}",
        "hunter": f"https://hunter.io/email-lookup/{encoded}",
        "epieos": f"https://epieos.com/?q={encoded}",
    }


# ---------------------------------------------------------------------------
# EmailRep.io
# ---------------------------------------------------------------------------

async def _query_emailrep(
    client: httpx.AsyncClient,
    email: str,
    report: EmailReport,
) -> None:
    """Query EmailRep.io for email reputation data."""
    api_key = os.environ.get("GHOST_EMAILREP_KEY", "")
    headers: dict[str, str] = {"User-Agent": "GhostMCP-OSINT"}
    if api_key:
        headers["Key"] = api_key

    try:
        resp = await client.get(f"{EMAILREP_URL}/{quote(email, safe='')}", headers=headers)
        if resp.status_code == 200:
            data = resp.json()
            report.reputation = {
                "score": data.get("reputation", ""),
                "suspicious": data.get("suspicious", False),
                "references": data.get("references", 0),
                "details": data.get("details", {}),
            }
        elif resp.status_code == 429:
            report.errors["emailrep"] = "Rate limited — set GHOST_EMAILREP_KEY for higher limits"
        else:
            report.errors["emailrep"] = f"HTTP {resp.status_code}"
    except (httpx.TimeoutException, httpx.ConnectError) as exc:
        report.errors["emailrep"] = str(exc)


# ---------------------------------------------------------------------------
# Holehe (subprocess)
# ---------------------------------------------------------------------------

async def _query_holehe(email: str, report: EmailReport) -> None:
    """Run holehe as a subprocess to discover account registrations.

    Holehe checks 100+ sites for email registration.  We shell out to the
    CLI because its internal async loop conflicts with an already-running
    event loop.  If the ``holehe`` binary is not on PATH, we skip
    gracefully.
    """
    try:
        proc = await asyncio.create_subprocess_exec(
            "holehe", email, "--only-used", "--no-color",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=300)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            report.errors["holehe"] = "Timed out after 300 seconds"
            return

        if proc.returncode != 0:
            report.errors["holehe"] = f"Exit code {proc.returncode}"
            return

        # Parse output — holehe prints one site per line with [+] prefix for hits
        for line in stdout.decode(errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            # Lines like: "[+] example.com"
            if line.startswith("[+]"):
                site = line[3:].strip().rstrip(".")
                if site:
                    report.accounts_found.append(site)
    except FileNotFoundError:
        report.errors["holehe"] = "holehe not installed — pip install holehe"
    except Exception as exc:
        report.errors["holehe"] = str(exc)


# ---------------------------------------------------------------------------
# Hunter.io
# ---------------------------------------------------------------------------

async def _query_hunter(
    client: httpx.AsyncClient,
    email: str,
    report: EmailReport,
) -> None:
    """Query Hunter.io for email enrichment (name, position, company, socials)."""
    api_key = os.environ.get("GHOST_HUNTER_KEY", "")
    if not api_key:
        report.errors["hunter"] = "GHOST_HUNTER_KEY not set"
        return

    try:
        resp = await client.get(
            HUNTER_URL,
            params={"email": email, "api_key": api_key},
        )
        if resp.status_code == 200:
            data = resp.json().get("data", {})
            report.hunter_enrichment = {
                "first_name": data.get("first_name", ""),
                "last_name": data.get("last_name", ""),
                "position": data.get("position", ""),
                "company": data.get("company", ""),
                "linkedin_url": data.get("linkedin_url", ""),
                "twitter": data.get("twitter", ""),
                "phone_number": data.get("phone_number", ""),
            }
        elif resp.status_code == 401:
            report.errors["hunter"] = "Invalid GHOST_HUNTER_KEY"
        elif resp.status_code == 429:
            report.errors["hunter"] = "Hunter.io rate limit exceeded"
        else:
            report.errors["hunter"] = f"HTTP {resp.status_code}"
    except (httpx.TimeoutException, httpx.ConnectError) as exc:
        report.errors["hunter"] = str(exc)


# ---------------------------------------------------------------------------
# HIBP (Have I Been Pwned)
# ---------------------------------------------------------------------------

async def _query_hibp(
    client: httpx.AsyncClient,
    email: str,
    report: EmailReport,
) -> None:
    """Query Have I Been Pwned for breach data."""
    api_key = os.environ.get("GHOST_HIBP_KEY", "")
    if not api_key:
        report.errors["hibp"] = "GHOST_HIBP_KEY not set"
        return

    headers = {
        "hibp-api-key": api_key,
        "user-agent": "GhostMCP-OSINT",
    }

    try:
        resp = await client.get(
            f"{HIBP_URL}/{quote(email, safe='')}",
            params={"truncateResponse": "true"},
            headers=headers,
        )
        if resp.status_code == 200:
            data = resp.json()
            report.breaches = [b.get("Name", "") for b in data if b.get("Name")]
            report.breach_count = len(report.breaches)
        elif resp.status_code == 404:
            # No breaches found — this is a good result
            report.breach_count = 0
        elif resp.status_code == 401:
            report.errors["hibp"] = "Invalid GHOST_HIBP_KEY"
        elif resp.status_code == 429:
            report.errors["hibp"] = "HIBP rate limit exceeded"
        else:
            report.errors["hibp"] = f"HTTP {resp.status_code}"
    except (httpx.TimeoutException, httpx.ConnectError) as exc:
        report.errors["hibp"] = str(exc)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

async def email_lookup(
    email: str,
    include_holehe: bool = True,
    include_hunter: bool = False,
) -> EmailReport:
    """Run a comprehensive email intelligence lookup.

    Args:
        email: Target email address.
        include_holehe: Run Holehe site-registration scan (slow, 2-5 min).
        include_hunter: Query Hunter.io for enrichment (requires paid key,
            skipped for free providers like gmail/yahoo).

    Returns:
        EmailReport with results from all queried services.
    """
    email = email.strip().lower()
    valid, domain = _basic_validate(email)
    is_free = domain.lower() in FREE_PROVIDERS if domain else False

    report = EmailReport(
        email=email,
        valid=valid,
        domain=domain,
        is_free_provider=is_free,
        search_urls=_build_search_urls(email),
    )

    if not valid:
        report.errors["validation"] = "Invalid email format"
        return report

    # Build async tasks -------------------------------------------------------
    # Holehe runs as a subprocess — start it independently
    holehe_task = None
    if include_holehe:
        holehe_task = asyncio.create_task(_query_holehe(email, report))

    async with httpx.AsyncClient(timeout=TIMEOUT) as client:
        http_tasks = [
            _query_emailrep(client, email, report),
            _query_hibp(client, email, report),
        ]

        # Hunter.io — only for non-free-provider domains when explicitly requested
        if include_hunter and not is_free:
            http_tasks.append(_query_hunter(client, email, report))

        await asyncio.gather(*http_tasks)

    # Wait for holehe if it was started
    if holehe_task is not None:
        await holehe_task

    return report
