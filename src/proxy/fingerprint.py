"""Browser fingerprint rotation for stealth requests."""

from __future__ import annotations

import random
from typing import Optional

from ..utils.config import ParanoiaLevel


# Realistic User-Agent strings — updated periodically
_CHROME_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
]

_FIREFOX_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.4; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0",
]

_SAFARI_UAS = [
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
]

_ALL_UAS = _CHROME_UAS + _FIREFOX_UAS + _SAFARI_UAS

_ACCEPT_LANGUAGES = [
    "en-US,en;q=0.9",
    "en-GB,en;q=0.9,en-US;q=0.8",
    "en-US,en;q=0.9,es;q=0.8",
    "en-US,en;q=0.9,fr;q=0.8",
    "en-US,en;q=0.9,de;q=0.7",
    "en-CA,en;q=0.9,fr-CA;q=0.8",
]


def get_headers(paranoia_level: Optional[str | ParanoiaLevel] = None) -> dict[str, str]:
    """Generate realistic browser headers for the given paranoia level.

    Higher paranoia levels get more randomization.
    All levels get a realistic fingerprint — even casual mode shouldn't
    send python-httpx as the User-Agent.

    Args:
        paranoia_level: Controls how much randomization is applied.

    Returns:
        Dict of HTTP headers suitable for httpx requests.
    """
    if isinstance(paranoia_level, str):
        paranoia_level = ParanoiaLevel(paranoia_level)
    if paranoia_level is None:
        paranoia_level = ParanoiaLevel.CASUAL

    ua = random.choice(_ALL_UAS)
    lang = random.choice(_ACCEPT_LANGUAGES)

    headers = {
        "User-Agent": ua,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": lang,
        "Accept-Encoding": "gzip, deflate, br",
        "DNT": "1",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
    }

    # Ghost/midnight: strip potential fingerprint leaks
    if paranoia_level in (ParanoiaLevel.GHOST, ParanoiaLevel.MIDNIGHT):
        # Use Tor Browser's standard UA for consistency with other Tor users
        headers["User-Agent"] = (
            "Mozilla/5.0 (Windows NT 10.0; rv:128.0) Gecko/20100101 Firefox/128.0"
        )
        headers["Accept-Language"] = "en-US,en;q=0.5"
        # Remove DNT — Tor Browser doesn't send it by default
        del headers["DNT"]

    return headers
