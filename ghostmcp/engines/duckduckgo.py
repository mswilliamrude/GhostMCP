"""DuckDuckGo Lite search engine scraper with optional TLS fingerprint mimicry."""

from __future__ import annotations

import asyncio
import re
import sys
from html import unescape
from typing import Optional
from urllib.parse import unquote, urlparse, parse_qs

import httpx

from .base import SearchEngine, SearchResult, SearchEngineError, RateLimitError

# Try curl_cffi for TLS fingerprint mimicry (looks like a real browser)
try:
    from curl_cffi.requests import AsyncSession as CurlSession
    HAS_CURL_CFFI = True
except ImportError:
    HAS_CURL_CFFI = False


class DuckDuckGoEngine(SearchEngine):
    """DuckDuckGo Lite scraper — no API key required.

    Uses the lightweight lite.duckduckgo.com endpoint (table-based HTML).
    More reliable than html.duckduckgo.com which returns 202/blocks.
    Supports proxy passthrough for ghost/midnight paranoia modes.
    Uses curl_cffi for TLS fingerprint mimicry when available.
    """

    name = "duckduckgo"
    min_delay = 2.0  # DDG is aggressive about rate limiting
    BASE_URL = "https://lite.duckduckgo.com/lite/"
    USER_AGENT = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    )

    async def search(self, query: str, num_results: int = 10) -> list[SearchResult]:
        """Search DuckDuckGo via Lite HTML endpoint.

        Handles DDG's 202 throttle responses with exponential backoff retry.
        Uses curl_cffi when available for TLS fingerprint consistency.

        Args:
            query: Search query string.
            num_results: Max results to extract (capped at ~30 per page).

        Returns:
            List of parsed SearchResult objects.
        """
        await self._rate_limit()

        if HAS_CURL_CFFI:
            html = await self._fetch_curl(query)
        else:
            html = await self._fetch_httpx(query)

        if html is None:
            return []

        return self._parse_lite_html(html, num_results)

    async def _fetch_curl(self, query: str) -> Optional[str]:
        """Fetch DDG Lite using curl_cffi with Chrome TLS fingerprint."""
        proxy_url = self.proxy.get("all") if self.proxy else None
        max_retries = 3
        backoff = 5.0

        headers = {
            "User-Agent": self.USER_AGENT,
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        }

        try:
            async with CurlSession() as session:
                for attempt in range(max_retries):
                    resp = await session.post(
                        self.BASE_URL,
                        data={"q": query, "kl": ""},
                        headers=headers,
                        proxy=proxy_url,
                        impersonate="chrome124",
                        timeout=30,
                        allow_redirects=True,
                    )

                    if resp.status_code == 202:
                        # DDG throttle — wait and retry
                        if attempt < max_retries - 1:
                            await asyncio.sleep(backoff * (attempt + 1))
                            continue
                        return None

                    if resp.status_code == 429:
                        raise RateLimitError(self.name, "Rate limited by DuckDuckGo")

                    if resp.status_code != 200:
                        raise SearchEngineError(
                            self.name, f"HTTP {resp.status_code}"
                        )
                    return resp.text
        except (RateLimitError, SearchEngineError):
            raise
        except Exception as e:
            raise SearchEngineError(self.name, f"curl_cffi request failed: {e}")

        return None

    async def _fetch_httpx(self, query: str) -> Optional[str]:
        """Fetch DDG Lite using httpx (fallback when curl_cffi not available)."""
        transport = None
        if self.proxy:
            transport = httpx.AsyncHTTPTransport(proxy=self.proxy.get("all"))

        max_retries = 3
        backoff = 5.0

        try:
            async with httpx.AsyncClient(
                transport=transport,
                timeout=30.0,
                follow_redirects=True,
            ) as client:
                for attempt in range(max_retries):
                    resp = await client.post(
                        self.BASE_URL,
                        data={"q": query, "kl": ""},
                        headers={
                            "User-Agent": self.USER_AGENT,
                            "Content-Type": "application/x-www-form-urlencoded",
                        },
                    )

                    if resp.status_code == 202:
                        # DDG throttle — wait and retry
                        if attempt < max_retries - 1:
                            await asyncio.sleep(backoff * (attempt + 1))
                            continue
                        return None

                    resp.raise_for_status()
                    return resp.text
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 429:
                raise RateLimitError(self.name, "Rate limited by DuckDuckGo")
            raise SearchEngineError(self.name, f"HTTP {e.response.status_code}")
        except httpx.RequestError as e:
            raise SearchEngineError(self.name, f"Request failed: {e}")

        return None

    def _parse_lite_html(self, html: str, num_results: int) -> list[SearchResult]:
        """Parse DuckDuckGo Lite results page.

        DDG Lite format (table-based):
          <tr>
            <td>1.&nbsp;</td>
            <td><a rel="nofollow" href="URL" class='result-link'>Title</a></td>
          </tr>
          <tr>
            <td>&nbsp;</td>
            <td class='result-snippet'>Snippet text...</td>
          </tr>

        Args:
            html: Raw HTML response from DDG Lite.
            num_results: Maximum results to return.

        Returns:
            Parsed search results.
        """
        results: list[SearchResult] = []

        # Extract all result links: <a rel="nofollow" href="URL" class='result-link'>Title</a>
        links = re.findall(
            r"""<a\s+rel=["']nofollow["']\s+href=["'](https?://[^"']+)["']\s+class=["']result-link["'][^>]*>(.*?)</a>""",
            html,
            re.DOTALL,
        )

        # Extract all snippets: <td class='result-snippet'>...</td>
        snippets = re.findall(
            r"""class=["']result-snippet["'][^>]*>(.*?)</td>""",
            html,
            re.DOTALL,
        )

        for i, (url, raw_title) in enumerate(links[:num_results]):
            title = self._strip_tags(unescape(raw_title))
            snippet = ""
            if i < len(snippets):
                snippet = self._strip_tags(unescape(snippets[i]))

            # Skip DDG internal links
            if "duckduckgo.com" in url:
                continue

            if title and url:
                results.append(SearchResult(
                    title=title,
                    url=url,
                    snippet=snippet,
                    source_engine=self.name,
                ))

        return results

    @staticmethod
    def _strip_tags(text: str) -> str:
        """Remove HTML tags and normalize whitespace."""
        clean = re.sub(r"<[^>]+>", "", text)
        clean = re.sub(r"\s+", " ", clean)
        return clean.strip()
