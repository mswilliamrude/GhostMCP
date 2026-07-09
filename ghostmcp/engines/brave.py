"""Brave Search API engine — privacy-focused, independent search index."""

from __future__ import annotations

import os
from typing import Optional

import httpx

from .base import SearchEngine, SearchResult, SearchEngineError


class BraveEngine(SearchEngine):
    """Brave Search API engine — independent index with structured JSON results.

    Uses the Brave Search API which provides 2,000 free queries per month.
    Privacy-focused, independent index (not a Google/Bing reskin).
    Structured JSON responses — no HTML parsing fragility.

    Requires GHOST_BRAVE_KEY environment variable.

    Sign up: https://brave.com/search/api/
    """

    name = "brave"
    min_delay = 1.0  # Conservative — generous limits but be polite

    API_URL = "https://api.search.brave.com/res/v1/web/search"

    def __init__(self, proxy: Optional[dict] = None, api_key: Optional[str] = None) -> None:
        """Initialize Brave Search engine.

        Args:
            proxy: Proxy config (optional).
            api_key: Brave API key. If None, reads from GHOST_BRAVE_KEY env var.
        """
        super().__init__(proxy=proxy)
        self.api_key = api_key or os.environ.get("GHOST_BRAVE_KEY", "")

    @property
    def available(self) -> bool:
        """Check if the engine is configured (has API key)."""
        return bool(self.api_key)

    async def search(
        self,
        query: str,
        num_results: int = 10,
        country: str = "",
        freshness: str = "",
    ) -> list[SearchResult]:
        """Search via Brave Search API.

        Args:
            query: Search query string.
            num_results: Max results to return (API max 20 per request).
            country: Country code filter (e.g. 'US', 'GB'). Empty = no filter.
            freshness: Time filter — 'pd' (past day), 'pw' (past week),
                      'pm' (past month), 'py' (past year). Empty = no filter.

        Returns:
            List of parsed SearchResult objects.

        Raises:
            SearchEngineError: On API errors or missing key.
        """
        if not self.api_key:
            raise SearchEngineError(
                self.name,
                "GHOST_BRAVE_KEY not set. "
                "Get a free key (2,000 searches/month) at https://brave.com/search/api/\n"
                "  1. Sign up at https://brave.com/search/api/\n"
                "  2. Create an app and get your API key\n"
                "  3. Export it: export GHOST_BRAVE_KEY='your-key-here'"
            )

        await self._rate_limit()

        # Brave API max is 20 per request — paginate if needed
        count = min(num_results, 20)

        params: dict = {
            "q": query,
            "count": count,
            "safesearch": "off",  # OSINT tool — don't filter results
        }
        if country:
            params["country"] = country
        if freshness:
            params["freshness"] = freshness

        headers = {
            "X-Subscription-Token": self.api_key,
            "Accept": "application/json",
            "Accept-Encoding": "gzip",
        }

        transport = None
        if self.proxy:
            transport = httpx.AsyncHTTPTransport(proxy=self.proxy.get("all"))

        try:
            async with httpx.AsyncClient(
                transport=transport,
                timeout=30.0,
            ) as client:
                resp = await client.get(
                    self.API_URL,
                    params=params,
                    headers=headers,
                )

                if resp.status_code == 401:
                    raise SearchEngineError(
                        self.name,
                        "Invalid GHOST_BRAVE_KEY. Check your key at "
                        "https://brave.com/search/api/"
                    )
                if resp.status_code == 403:
                    raise SearchEngineError(
                        self.name,
                        "Brave API access denied. Your plan may not include "
                        "web search, or your key is inactive."
                    )
                if resp.status_code == 429:
                    raise SearchEngineError(
                        self.name,
                        "Brave rate limit hit. Free tier: 2,000/month. "
                        "Check usage at https://brave.com/search/api/"
                    )
                resp.raise_for_status()

                data = resp.json()
        except SearchEngineError:
            raise
        except httpx.HTTPStatusError as e:
            raise SearchEngineError(self.name, f"API HTTP {e.response.status_code}")
        except httpx.TimeoutException:
            raise SearchEngineError(self.name, "Request timed out (30s)")
        except httpx.ConnectError:
            raise SearchEngineError(self.name, "Connection failed to api.search.brave.com")
        except httpx.RequestError as e:
            raise SearchEngineError(self.name, f"Request failed: {e}")

        results = self._parse_response(data, num_results)

        # If user wants more than 20 results, paginate
        if num_results > 20 and len(results) >= 20:
            try:
                params["offset"] = 20
                params["count"] = min(num_results - 20, 20)
                async with httpx.AsyncClient(
                    transport=transport,
                    timeout=30.0,
                ) as client:
                    resp = await client.get(
                        self.API_URL,
                        params=params,
                        headers=headers,
                    )
                    if resp.status_code == 200:
                        data2 = resp.json()
                        results.extend(self._parse_response(data2, num_results - 20))
            except Exception:
                pass  # Best effort — return what we have

        return results[:num_results]

    def _parse_response(self, data: dict, num_results: int) -> list[SearchResult]:
        """Parse Brave Search API JSON response into SearchResult objects.

        Brave returns results under data["web"]["results"].
        Each result has: title, url, description, age, language.

        Args:
            data: Parsed JSON response from Brave API.
            num_results: Maximum results to return.

        Returns:
            List of SearchResult objects.
        """
        results: list[SearchResult] = []

        web = data.get("web", {})
        web_results = web.get("results", [])

        for item in web_results[:num_results]:
            title = item.get("title", "")
            url = item.get("url", "")
            snippet = item.get("description", "")

            if not url:
                continue

            results.append(SearchResult(
                title=title or url,
                url=url,
                snippet=snippet,
                source_engine=self.name,
            ))

        return results
