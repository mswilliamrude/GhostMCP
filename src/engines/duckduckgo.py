"""DuckDuckGo HTML search engine scraper."""

from __future__ import annotations

import re
from html import unescape
from urllib.parse import unquote, urlparse, parse_qs

import httpx

from .base import SearchEngine, SearchResult, SearchEngineError


class DuckDuckGoEngine(SearchEngine):
    """DuckDuckGo HTML scraper — no API key required.

    Fetches results from the lite HTML endpoint and parses them.
    Supports proxy passthrough for ghost/midnight paranoia modes.
    """

    name = "duckduckgo"
    min_delay = 2.0  # DDG is aggressive about rate limiting
    BASE_URL = "https://html.duckduckgo.com/html/"

    async def search(self, query: str, num_results: int = 10) -> list[SearchResult]:
        """Search DuckDuckGo via HTML scraping.

        Args:
            query: Search query string.
            num_results: Max results to extract (capped at ~30 per page).

        Returns:
            List of parsed SearchResult objects.
        """
        await self._rate_limit()

        transport = None
        if self.proxy:
            transport = httpx.AsyncHTTPTransport(proxy=self.proxy.get("all"))

        try:
            async with httpx.AsyncClient(
                transport=transport,
                timeout=30.0,
                follow_redirects=True,
            ) as client:
                resp = await client.post(
                    self.BASE_URL,
                    data={"q": query, "b": ""},
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                )
                resp.raise_for_status()
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 429:
                from .base import RateLimitError
                raise RateLimitError(self.name, "Rate limited by DuckDuckGo")
            raise SearchEngineError(self.name, f"HTTP {e.response.status_code}")
        except httpx.RequestError as e:
            raise SearchEngineError(self.name, f"Request failed: {e}")

        return self._parse_html(resp.text, num_results)

    def _parse_html(self, html: str, num_results: int) -> list[SearchResult]:
        """Parse DuckDuckGo HTML results page.

        Uses regex parsing — no heavy dependencies needed.

        Args:
            html: Raw HTML response from DDG.
            num_results: Maximum results to return.

        Returns:
            Parsed search results.
        """
        results: list[SearchResult] = []

        # DDG HTML result blocks are in <div class="result ...">
        # Each contains: <a class="result__a"> (title+url), <a class="result__snippet"> (snippet)
        result_blocks = re.findall(
            r'<div[^>]*class="[^"]*result[^"]*results_links[^"]*"[^>]*>(.*?)</div>\s*</div>',
            html,
            re.DOTALL,
        )

        # Fallback: try individual component extraction if block parsing fails
        if not result_blocks:
            return self._parse_flat(html, num_results)

        for block in result_blocks[:num_results]:
            title, url, snippet = self._extract_from_block(block)
            if title and url:
                results.append(SearchResult(
                    title=title,
                    url=url,
                    snippet=snippet or "",
                    source_engine=self.name,
                ))

        return results

    def _parse_flat(self, html: str, num_results: int) -> list[SearchResult]:
        """Fallback flat regex parsing when block parsing fails."""
        results: list[SearchResult] = []

        # Extract links with class result__a
        links = re.findall(
            r'<a[^>]*class="result__a"[^>]*href="([^"]*)"[^>]*>(.*?)</a>',
            html,
            re.DOTALL,
        )
        # Extract snippets
        snippets = re.findall(
            r'<a[^>]*class="result__snippet"[^>]*>(.*?)</a>',
            html,
            re.DOTALL,
        )

        for i, (raw_url, raw_title) in enumerate(links[:num_results]):
            url = self._clean_url(raw_url)
            title = self._strip_tags(unescape(raw_title))
            snippet = ""
            if i < len(snippets):
                snippet = self._strip_tags(unescape(snippets[i]))

            if title and url:
                results.append(SearchResult(
                    title=title,
                    url=url,
                    snippet=snippet,
                    source_engine=self.name,
                ))

        return results

    def _extract_from_block(self, block: str) -> tuple[str, str, str]:
        """Extract title, url, snippet from a single result block."""
        title = ""
        url = ""
        snippet = ""

        # Title + URL from result__a link
        link_match = re.search(
            r'<a[^>]*class="result__a"[^>]*href="([^"]*)"[^>]*>(.*?)</a>',
            block,
            re.DOTALL,
        )
        if link_match:
            url = self._clean_url(link_match.group(1))
            title = self._strip_tags(unescape(link_match.group(2)))

        # Snippet from result__snippet
        snippet_match = re.search(
            r'<a[^>]*class="result__snippet"[^>]*>(.*?)</a>',
            block,
            re.DOTALL,
        )
        if snippet_match:
            snippet = self._strip_tags(unescape(snippet_match.group(1)))

        return title, url, snippet

    @staticmethod
    def _clean_url(raw_url: str) -> str:
        """Extract actual URL from DDG redirect wrapper."""
        # DDG wraps URLs: //duckduckgo.com/l/?uddg=<encoded_url>&...
        if "uddg=" in raw_url:
            parsed = urlparse(raw_url)
            params = parse_qs(parsed.query)
            if "uddg" in params:
                return unquote(params["uddg"][0])
        # Direct URL
        if raw_url.startswith("//"):
            return "https:" + raw_url
        return raw_url

    @staticmethod
    def _strip_tags(text: str) -> str:
        """Remove HTML tags and normalize whitespace."""
        clean = re.sub(r"<[^>]+>", "", text)
        clean = re.sub(r"\s+", " ", clean)
        return clean.strip()
