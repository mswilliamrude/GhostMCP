"""Google HTML search engine scraper with TLS fingerprint mimicry."""

from __future__ import annotations

import re
import sys
import asyncio
from html import unescape
from typing import Optional
from urllib.parse import quote_plus

import httpx

from .base import SearchEngine, SearchResult, SearchEngineError, RateLimitError
from ..proxy.fingerprint import get_headers

# Try curl_cffi for TLS fingerprint mimicry (looks like a real browser)
try:
    from curl_cffi.requests import AsyncSession as CurlSession
    HAS_CURL_CFFI = True
except ImportError:
    HAS_CURL_CFFI = False
    print(
        "[GhostMCP] curl_cffi not installed — Google scraper using httpx fallback. "
        "Install curl_cffi for better stealth: pip install curl_cffi",
        file=sys.stderr,
    )


class GoogleEngine(SearchEngine):
    """Google HTML SERP scraper.

    Uses curl_cffi for TLS fingerprint mimicry when available,
    falls back to httpx with stealth headers. Handles consent pages
    and CAPTCHA detection gracefully.
    """

    name = "google"
    min_delay = 5.0  # Google is aggressive about rate-limiting

    BASE_URL = "https://www.google.com/search"

    def __init__(self, proxy: Optional[dict] = None, paranoia: str = "cautious") -> None:
        """Initialize Google engine.

        Args:
            proxy: Proxy config dict (e.g. {"all": "socks5://..."}).
            paranoia: Paranoia level for header generation.
        """
        super().__init__(proxy=proxy)
        self.paranoia = paranoia

    async def search(self, query: str, num_results: int = 10) -> list[SearchResult]:
        """Search Google via HTML scraping.

        Args:
            query: Search query string.
            num_results: Max results to return (Google returns up to ~100).

        Returns:
            List of parsed SearchResult objects.

        Raises:
            SearchEngineError: On request failure or CAPTCHA detection.
            RateLimitError: When rate-limited (HTTP 429).
        """
        await self._rate_limit()

        url = f"{self.BASE_URL}?q={quote_plus(query)}&num={num_results}"
        headers = get_headers(self.paranoia)
        # Google-specific: signal we accept the page without consent cookie
        headers["Cookie"] = "CONSENT=PENDING+987"

        html = await self._fetch(url, headers)
        return self._parse_serp(html, num_results)

    async def _fetch(self, url: str, headers: dict[str, str]) -> str:
        """Fetch URL using curl_cffi (preferred) or httpx fallback.

        Args:
            url: URL to fetch.
            headers: Request headers.

        Returns:
            Response HTML body.
        """
        if HAS_CURL_CFFI:
            return await self._fetch_curl(url, headers)
        return await self._fetch_httpx(url, headers)

    async def _fetch_curl(self, url: str, headers: dict[str, str]) -> str:
        """Fetch using curl_cffi with Chrome TLS fingerprint."""
        proxy_url = self.proxy.get("all") if self.proxy else None

        try:
            async with CurlSession() as session:
                resp = await session.get(
                    url,
                    headers=headers,
                    proxy=proxy_url,
                    impersonate="chrome124",
                    timeout=30,
                    allow_redirects=True,
                )
                if resp.status_code == 429:
                    raise RateLimitError(self.name, "Rate limited by Google (429)")
                if resp.status_code != 200:
                    raise SearchEngineError(
                        self.name, f"HTTP {resp.status_code}"
                    )
                return resp.text
        except (RateLimitError, SearchEngineError):
            raise
        except Exception as e:
            raise SearchEngineError(self.name, f"curl_cffi request failed: {e}")

    async def _fetch_httpx(self, url: str, headers: dict[str, str]) -> str:
        """Fetch using httpx (fallback when curl_cffi not available)."""
        transport = None
        if self.proxy:
            transport = httpx.AsyncHTTPTransport(proxy=self.proxy.get("all"))

        try:
            async with httpx.AsyncClient(
                transport=transport,
                timeout=30.0,
                follow_redirects=True,
            ) as client:
                resp = await client.get(url, headers=headers)
                if resp.status_code == 429:
                    raise RateLimitError(self.name, "Rate limited by Google (429)")
                if resp.status_code != 200:
                    raise SearchEngineError(
                        self.name, f"HTTP {resp.status_code}"
                    )
                return resp.text
        except (RateLimitError, SearchEngineError):
            raise
        except httpx.RequestError as e:
            raise SearchEngineError(self.name, f"httpx request failed: {e}")

    def _parse_serp(self, html: str, num_results: int) -> list[SearchResult]:
        """Parse Google SERP HTML into structured results.

        Handles consent/CAPTCHA detection before parsing.

        Args:
            html: Raw Google results HTML.
            num_results: Maximum results to extract.

        Returns:
            List of SearchResult objects.

        Raises:
            SearchEngineError: If CAPTCHA or consent page detected.
        """
        # Detect CAPTCHA
        if self._is_captcha(html):
            raise SearchEngineError(
                self.name,
                "CAPTCHA detected. Try increasing paranoia level or wait before retrying."
            )

        # Detect consent redirect
        if self._is_consent_page(html):
            raise SearchEngineError(
                self.name,
                "Google consent page detected. Cookie bypass failed."
            )

        results: list[SearchResult] = []

        # Strategy 1: Modern Google SERP — <div class="g"> blocks
        blocks = re.findall(r'<div class="g"[^>]*>(.*?)</div>\s*(?=<div class="g"|$)', html, re.DOTALL)
        if not blocks:
            # Strategy 2: Extract from <a> tags with /url?q= pattern
            blocks = re.findall(
                r'<div[^>]*class="[^"]*tF2Cxc[^"]*"[^>]*>(.*?)</div>',
                html,
                re.DOTALL,
            )

        if blocks:
            for block in blocks[:num_results]:
                result = self._extract_result_block(block)
                if result:
                    results.append(result)

        # Strategy 3: Flat extraction as last resort
        if not results:
            results = self._extract_flat(html, num_results)

        return results

    def _extract_result_block(self, block: str) -> Optional[SearchResult]:
        """Extract a single result from a SERP block."""
        # URL: look for href with actual URL
        url_match = re.search(
            r'<a[^>]*href="(/url\?q=([^&"]+)|https?://[^"]+)"',
            block,
        )
        if not url_match:
            return None

        raw_url = url_match.group(1)
        if raw_url.startswith("/url?q="):
            # Google redirect URL — extract actual target
            url = re.sub(r"^/url\?q=", "", raw_url)
            url = url.split("&")[0]
            from urllib.parse import unquote
            url = unquote(url)
        else:
            url = raw_url

        # Skip google internal links
        if "google.com" in url and "/search" in url:
            return None

        # Title: first <h3> content
        title_match = re.search(r'<h3[^>]*>(.*?)</h3>', block, re.DOTALL)
        title = self._clean_text(title_match.group(1)) if title_match else ""

        # Snippet: various possible containers
        snippet = ""
        for pattern in [
            r'<span class="[^"]*">(?:<em>)?(.*?)(?:</em>)?</span>',
            r'<div[^>]*class="[^"]*VwiC3b[^"]*"[^>]*>(.*?)</div>',
            r'<div[^>]*data-sncf="[^"]*"[^>]*>(.*?)</div>',
        ]:
            snippet_match = re.search(pattern, block, re.DOTALL)
            if snippet_match:
                candidate = self._clean_text(snippet_match.group(1))
                if len(candidate) > len(snippet):
                    snippet = candidate

        if not title and not url:
            return None

        return SearchResult(
            title=title or url,
            url=url,
            snippet=snippet,
            source_engine=self.name,
        )

    def _extract_flat(self, html: str, num_results: int) -> list[SearchResult]:
        """Last-resort flat extraction from Google HTML."""
        results: list[SearchResult] = []

        # Find all /url?q= links with surrounding context
        links = re.findall(
            r'<a[^>]*href="/url\?q=(https?://[^&"]+)[^"]*"[^>]*>(.*?)</a>',
            html,
            re.DOTALL,
        )

        for raw_url, raw_title in links[:num_results]:
            from urllib.parse import unquote
            url = unquote(raw_url)

            if "google.com" in url:
                continue

            title = self._clean_text(raw_title)
            if not title:
                title = url

            results.append(SearchResult(
                title=title,
                url=url,
                snippet="",
                source_engine=self.name,
            ))

        return results

    @staticmethod
    def _is_captcha(html: str) -> bool:
        """Detect Google CAPTCHA/bot-check pages."""
        captcha_signals = [
            "unusual traffic",
            "captcha",
            "recaptcha",
            "/sorry/",
            "detected unusual traffic",
        ]
        html_lower = html.lower()
        return any(signal in html_lower for signal in captcha_signals)

    @staticmethod
    def _is_consent_page(html: str) -> bool:
        """Detect Google consent/cookie acceptance page."""
        consent_signals = [
            "consent.google.com",
            "Before you continue to Google",
            "id=\"CXQnmb\"",
        ]
        return any(signal in html for signal in consent_signals)

    @staticmethod
    def _clean_text(html_text: str) -> str:
        """Strip HTML tags and normalize whitespace."""
        text = re.sub(r"<[^>]+>", "", html_text)
        text = unescape(text)
        text = re.sub(r"\s+", " ", text)
        return text.strip()
