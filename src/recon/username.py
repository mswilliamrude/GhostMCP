"""Username enumeration module — discover accounts across social platforms."""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field

import httpx

TIMEOUT = 10.0
BUILTIN_CHECK_TIMEOUT = 10.0

# Sites for the builtin fallback checker.
# Each entry: (site_name, url_template, category, check_method)
# check_method: "status" = 200 means exists, "json" = Reddit-style JSON check
_BUILTIN_SITES: list[tuple[str, str, str, str]] = [
    ("GitHub", "https://github.com/{}", "development", "status"),
    ("Twitter/X", "https://x.com/{}", "social", "status"),
    ("Instagram", "https://instagram.com/{}/", "social", "status"),
    ("Reddit", "https://reddit.com/user/{}/about.json", "social", "json"),
    ("YouTube", "https://youtube.com/@{}", "social", "status"),
    ("TikTok", "https://tiktok.com/@{}", "social", "status"),
    ("Pinterest", "https://pinterest.com/{}/", "social", "status"),
    ("Medium", "https://medium.com/@{}", "social", "status"),
    ("Twitch", "https://twitch.tv/{}", "social", "status"),
    ("Steam", "https://steamcommunity.com/id/{}", "gaming", "status"),
    ("Keybase", "https://keybase.io/{}", "security", "status"),
    ("HackerNews", "https://news.ycombinator.com/user?id={}", "development", "status"),
    ("GitLab", "https://gitlab.com/{}", "development", "status"),
    ("Bitbucket", "https://bitbucket.org/{}/", "development", "status"),
    ("SoundCloud", "https://soundcloud.com/{}", "music", "status"),
    ("Flickr", "https://flickr.com/people/{}/", "photography", "status"),
    ("DeviantArt", "https://deviantart.com/{}", "art", "status"),
]

# URL-only sites (no reliable programmatic check)
_URL_ONLY_SITES: list[tuple[str, str, str]] = [
    ("LinkedIn", "https://linkedin.com/in/{}", "professional"),
    ("StackOverflow", "https://stackoverflow.com/users?q={}", "development"),
    ("Spotify", "https://open.spotify.com/search/{}", "music"),
]


@dataclass
class UsernameReport:
    username: str
    sites_checked: int = 0
    accounts_found: list[dict] = field(default_factory=list)
    accounts_not_found_count: int = 0
    scan_time_seconds: float = 0.0
    tool_used: str = "builtin"
    timed_out: bool = False
    search_urls: dict = field(default_factory=dict)
    error: str | None = None


# ---------------------------------------------------------------------------
# Search URL generation
# ---------------------------------------------------------------------------

def _build_search_urls(username: str) -> dict[str, str]:
    """Generate OSINT search URLs for a username."""
    return {
        "namechk": f"https://namechk.com/username/{username}",
        "knowem": f"https://knowem.com/checkusernames.php?u={username}",
        "whatsmyname": f"https://whatsmyname.app/?q={username}",
    }


# ---------------------------------------------------------------------------
# Maigret / Sherlock subprocess
# ---------------------------------------------------------------------------

async def _run_external_tool(
    username: str,
    max_sites: int,
    timeout: int,
) -> UsernameReport | None:
    """Try to run maigret or sherlock as a subprocess.

    Returns a populated UsernameReport, or None if neither tool is installed.
    """
    # Prefer maigret (more sites, better accuracy), fall back to sherlock
    tool_name: str | None = None
    cmd: list[str] = []

    for candidate in ("maigret", "sherlock"):
        # Check if the binary exists on PATH
        check = await asyncio.create_subprocess_exec(
            "which", candidate,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await check.communicate()
        if check.returncode == 0:
            tool_name = candidate
            break

    if tool_name is None:
        return None

    if tool_name == "maigret":
        cmd = [
            "maigret", username,
            "--top-sites", str(max_sites),
            "--no-color",
            "--timeout", str(min(timeout, 30)),
        ]
    else:
        # sherlock
        cmd = [
            "sherlock", username,
            "--timeout", str(min(timeout, 30)),
            "--print-found",
        ]

    start = time.monotonic()
    report = UsernameReport(
        username=username,
        tool_used=tool_name,
        search_urls=_build_search_urls(username),
    )

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            report.timed_out = True
            # Still try to read any partial output
            try:
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=5)
            except Exception:
                stdout = b""

        elapsed = time.monotonic() - start
        report.scan_time_seconds = round(elapsed, 2)

        # Parse output lines for found accounts
        found_count = 0
        not_found_count = 0

        for line in stdout.decode(errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue

            # maigret output: "[+] SiteName: https://url"
            # sherlock output: "[+] SiteName: https://url" or just "SiteName: https://url"
            if "[+]" in line or ("http" in line and "[-]" not in line and "[*]" not in line):
                # Extract site name and URL
                cleaned = line.lstrip("[+] ").strip()
                if ": http" in cleaned:
                    parts = cleaned.split(": http", 1)
                    site_name = parts[0].strip()
                    url = "http" + parts[1].strip()
                elif "http" in cleaned:
                    url = cleaned
                    site_name = ""
                else:
                    continue

                report.accounts_found.append({
                    "site_name": site_name,
                    "url": url,
                    "category": "",
                })
                found_count += 1
            elif "[-]" in line or "Not Found" in line:
                not_found_count += 1

        report.sites_checked = found_count + not_found_count
        report.accounts_not_found_count = not_found_count

    except FileNotFoundError:
        return None
    except Exception as exc:
        report.error = str(exc)

    return report


# ---------------------------------------------------------------------------
# Builtin checker (fallback)
# ---------------------------------------------------------------------------

async def _check_site(
    client: httpx.AsyncClient,
    username: str,
    site_name: str,
    url_template: str,
    category: str,
    check_method: str,
) -> dict | None:
    """Check a single site for username existence.

    Returns an account dict if found, None otherwise.
    """
    url = url_template.format(username)
    try:
        resp = await client.get(url, follow_redirects=False)

        if check_method == "json":
            # Reddit-style: 200 with valid JSON = exists
            if resp.status_code == 200:
                try:
                    data = resp.json()
                    # Reddit returns {"error": 404} for missing users
                    if isinstance(data, dict) and data.get("error"):
                        return None
                    return {"site_name": site_name, "url": url, "category": category}
                except Exception:
                    return None
        else:
            # Standard status code check
            if resp.status_code == 200:
                return {"site_name": site_name, "url": url, "category": category}

    except (httpx.TimeoutException, httpx.ConnectError, httpx.TooManyRedirects):
        pass
    except Exception:
        pass

    return None


async def _builtin_check(username: str) -> UsernameReport:
    """Check ~20 major sites directly via httpx as a fallback."""
    start = time.monotonic()
    report = UsernameReport(
        username=username,
        tool_used="builtin",
        search_urls=_build_search_urls(username),
    )

    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0.0.0 Safari/537.36"
        ),
    }

    async with httpx.AsyncClient(
        timeout=BUILTIN_CHECK_TIMEOUT,
        headers=headers,
    ) as client:
        tasks = [
            _check_site(client, username, name, url_tpl, cat, method)
            for name, url_tpl, cat, method in _BUILTIN_SITES
        ]
        results = await asyncio.gather(*tasks)

    found = [r for r in results if r is not None]
    report.accounts_found = found
    report.sites_checked = len(_BUILTIN_SITES)
    report.accounts_not_found_count = len(_BUILTIN_SITES) - len(found)

    # Add URL-only sites as found entries (always included, cannot verify)
    for site_name, url_tpl, category in _URL_ONLY_SITES:
        report.accounts_found.append({
            "site_name": f"{site_name} (url only)",
            "url": url_tpl.format(username),
            "category": category,
        })

    elapsed = time.monotonic() - start
    report.scan_time_seconds = round(elapsed, 2)
    return report


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

async def username_lookup(
    username: str,
    max_sites: int = 100,
    timeout: int = 120,
) -> UsernameReport:
    """Enumerate accounts associated with a username across social platforms.

    Tries maigret or sherlock first (subprocess). Falls back to a builtin
    checker that tests ~20 major sites directly via httpx.

    Args:
        username: Target username to search for.
        max_sites: Maximum sites to check when using maigret (default 100).
        timeout: Overall timeout in seconds for external tools (default 120).

    Returns:
        UsernameReport with discovered accounts and OSINT URLs.
    """
    username = username.strip()
    if not username:
        return UsernameReport(
            username=username,
            error="Empty username",
            search_urls=_build_search_urls(username),
        )

    # Try external tool first
    result = await _run_external_tool(username, max_sites, timeout)
    if result is not None:
        return result

    # Fall back to builtin checker
    return await _builtin_check(username)
