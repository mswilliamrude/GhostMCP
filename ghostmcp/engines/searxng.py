"""SearXNG metasearch engine — privacy-respecting aggregator across multiple search engines.

SearXNG aggregates results from Google, Bing, DuckDuckGo, Wikipedia, and many others
without tracking. Requires a SearXNG instance URL (self-hosted or public).

Set GHOST_SEARXNG_URL to your instance (e.g., https://searx.example.com or http://localhost:8888).
"""

from __future__ import annotations

import os
from typing import Optional

import httpx

from .base import SearchEngine, SearchResult, SearchEngineError


class SearXNGEngine(SearchEngine):
    """SearXNG metasearch engine — privacy-focused aggregator.

    SearXNG is a free, open-source metasearch engine that aggregates results
    from 70+ search engines without tracking. Self-hostable or use public instances.

    Requires GHOST_SEARXNG_URL environment variable pointing to an instance.

    Public instances: https://searx.space/ (but self-hosted preferred for OSINT)

    Features:
    - Aggregates Google, Bing, DuckDuckGo, Wikipedia, Reddit, GitHub, etc.
    - No tracking, no ads, no user profiling
    - JSON API for structured results
    - Category and engine filtering
    - Time range filtering
    """

    name = "searxng"
    min_delay = 1.0  # Be polite to the instance

    def __init__(
        self,
        proxy: Optional[dict] = None,
        instance_url: Optional[str] = None,
    ) -> None:
        """Initialize SearXNG engine.

        Args:
            proxy: Proxy config (optional).
            instance_url: SearXNG instance URL. If None, reads from GHOST_SEARXNG_URL.
        """
        super().__init__(proxy=proxy)
        self.instance_url = (instance_url or os.environ.get("GHOST_SEARXNG_URL", "")).rstrip("/")

    @property
    def available(self) -> bool:
        """Check if the engine is configured (has instance URL)."""
        return bool(self.instance_url)

    async def search(
        self,
        query: str,
        num_results: int = 10,
        categories: str = "general",
        engines: str = "",
        language: str = "en",
        time_range: str = "",
        safesearch: int = 0,
        pageno: int = 1,
    ) -> list[SearchResult]:
        """Search via SearXNG API.

        Args:
            query: Search query string.
            num_results: Max results to return (SearXNG returns ~10 per page).
            categories: Comma-separated categories: general, images, news, science, it, files, social media.
            engines: Comma-separated engines to use (empty = all in category).
                     Examples: google, bing, duckduckgo, wikipedia, reddit, github, arxiv.
            language: Language code (e.g., 'en', 'de', 'fr'). Default: en.
            time_range: Time filter: day, week, month, year. Empty = no filter.
            safesearch: SafeSearch level: 0 (off), 1 (moderate), 2 (strict). Default: 0.
            pageno: Page number (1-indexed). Default: 1.

        Returns:
            List of parsed SearchResult objects.

        Raises:
            SearchEngineError: On API errors or missing configuration.
        """
        if not self.instance_url:
            raise SearchEngineError(
                self.name,
                "GHOST_SEARXNG_URL not set. "
                "Point it to a SearXNG instance (self-hosted or public).\n"
                "  1. Self-host: docker run -p 8888:8080 searxng/searxng\n"
                "  2. Or use a public instance from https://searx.space/\n"
                "  3. Export: export GHOST_SEARXNG_URL='http://localhost:8888'"
            )

        await self._rate_limit()

        # Build request parameters
        params: dict = {
            "q": query,
            "format": "json",
            "categories": categories,
            "language": language,
            "safesearch": safesearch,
            "pageno": pageno,
        }

        if engines:
            params["engines"] = engines
        if time_range:
            params["time_range"] = time_range

        search_url = f"{self.instance_url}/search"

        transport = None
        if self.proxy:
            transport = httpx.AsyncHTTPTransport(proxy=self.proxy.get("all"))

        headers = {
            "Accept": "application/json",
            "User-Agent": "GhostMCP/1.0 (OSINT toolkit)",
        }

        try:
            async with httpx.AsyncClient(
                transport=transport,
                timeout=30.0,
                follow_redirects=True,
            ) as client:
                resp = await client.get(
                    search_url,
                    params=params,
                    headers=headers,
                )

                if resp.status_code == 429:
                    raise SearchEngineError(
                        self.name,
                        f"SearXNG rate limit hit at {self.instance_url}. "
                        "Try a different instance or wait."
                    )
                if resp.status_code == 403:
                    raise SearchEngineError(
                        self.name,
                        f"SearXNG instance at {self.instance_url} blocked the request. "
                        "The instance may have disabled API access or blocked bots."
                    )
                if resp.status_code == 404:
                    raise SearchEngineError(
                        self.name,
                        f"SearXNG search endpoint not found at {search_url}. "
                        "Check if the URL is correct and the instance is running."
                    )
                resp.raise_for_status()

                data = resp.json()

        except SearchEngineError:
            raise
        except httpx.HTTPStatusError as e:
            raise SearchEngineError(self.name, f"HTTP {e.response.status_code} from {self.instance_url}")
        except httpx.TimeoutException:
            raise SearchEngineError(self.name, f"Timeout connecting to {self.instance_url}")
        except httpx.ConnectError:
            raise SearchEngineError(self.name, f"Connection failed to {self.instance_url}")
        except httpx.RequestError as e:
            raise SearchEngineError(self.name, f"Request failed: {e}")

        results = self._parse_response(data, num_results)

        # Pagination: if user wants more results and we got a full page, fetch next page
        if num_results > len(results) and len(results) >= 10 and pageno < 5:
            try:
                more = await self.search(
                    query=query,
                    num_results=num_results - len(results),
                    categories=categories,
                    engines=engines,
                    language=language,
                    time_range=time_range,
                    safesearch=safesearch,
                    pageno=pageno + 1,
                )
                results.extend(more)
            except Exception:
                pass  # Best effort — return what we have

        return results[:num_results]

    def _parse_response(self, data: dict, num_results: int) -> list[SearchResult]:
        """Parse SearXNG JSON response into SearchResult objects.

        SearXNG returns:
        {
            "results": [
                {"title": "...", "url": "...", "content": "...", "engine": "google", ...}
            ],
            "suggestions": [...],
            "answers": [...],
            "infoboxes": [...]
        }
        """
        results: list[SearchResult] = []

        for item in data.get("results", [])[:num_results]:
            title = item.get("title", "")
            url = item.get("url", "")
            content = item.get("content", "")
            engine = item.get("engine", "searxng")

            if not url:
                continue

            # Prefix with the source engine for transparency
            source = f"searxng:{engine}" if engine else self.name

            results.append(SearchResult(
                title=title or url,
                url=url,
                snippet=content,
                source_engine=source,
            ))

        return results

    async def get_engines(self) -> dict:
        """Fetch available engines from the SearXNG instance.

        Returns dict with engine info: {engine_name: {categories, enabled, ...}}
        Useful for discovering what engines the instance supports.
        """
        if not self.instance_url:
            raise SearchEngineError(self.name, "GHOST_SEARXNG_URL not set")

        config_url = f"{self.instance_url}/config"

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(config_url)
                if resp.status_code == 200:
                    data = resp.json()
                    return data.get("engines", {})
        except Exception:
            pass

        return {}
