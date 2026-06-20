"""Bing Search API engine — Microsoft's search index via Cognitive Services."""

from __future__ import annotations

import os
from typing import Optional

import httpx

from .base import SearchEngine, SearchResult, SearchEngineError


class BingEngine(SearchEngine):
    """Bing Search API engine — Microsoft's search index.

    Uses the Bing Web Search API v7.0 via Azure Cognitive Services.
    Provides high-quality web results with structured JSON responses.

    Requires GHOST_BING_KEY environment variable (Azure Cognitive Services key).

    Sign up: https://www.microsoft.com/en-us/bing/apis/bing-web-search-api
    """

    name = "bing"
    min_delay = 1.0  # Conservative — generous limits but be polite

    API_URL = "https://api.bing.microsoft.com/v7.0/search"

    def __init__(self, proxy: Optional[dict] = None, api_key: Optional[str] = None) -> None:
        """Initialize Bing Search engine.

        Args:
            proxy: Proxy config (optional).
            api_key: Bing API key. If None, reads from GHOST_BING_KEY env var.
        """
        super().__init__(proxy=proxy)
        self.api_key = api_key or os.environ.get("GHOST_BING_KEY", "")

    @property
    def available(self) -> bool:
        """Check if the engine is configured (has API key)."""
        return bool(self.api_key)

    async def search(
        self,
        query: str,
        num_results: int = 10,
        market: str = "en-US",
        freshness: str = "",
    ) -> list[SearchResult]:
        """Search via Bing Web Search API.

        Args:
            query: Search query string.
            num_results: Max results to return (API max 50 per request).
            market: Market code for results (e.g. 'en-US', 'en-GB'). Default: 'en-US'.
            freshness: Time filter — 'Day', 'Week', 'Month'. Empty = no filter.

        Returns:
            List of parsed SearchResult objects.

        Raises:
            SearchEngineError: On API errors or missing key.
        """
        if not self.api_key:
            raise SearchEngineError(
                self.name,
                "GHOST_BING_KEY not set. "
                "Get a key at https://www.microsoft.com/en-us/bing/apis/bing-web-search-api\n"
                "  1. Create an Azure Cognitive Services resource\n"
                "  2. Get your Bing Search API key\n"
                "  3. Export it: export GHOST_BING_KEY='your-key-here'"
            )

        await self._rate_limit()

        # Bing API max is 50 per request
        count = min(max(1, num_results), 50)

        params: dict = {
            "q": query,
            "count": count,
            "mkt": market,
            "safeSearch": "Off",  # OSINT tool — don't filter results
        }
        if freshness:
            params["freshness"] = freshness

        headers = {
            "Ocp-Apim-Subscription-Key": self.api_key,
            "Accept": "application/json",
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
                        "Invalid GHOST_BING_KEY. Check your key at "
                        "https://portal.azure.com/"
                    )
                if resp.status_code == 403:
                    raise SearchEngineError(
                        self.name,
                        "Bing API access denied. Your subscription may be inactive "
                        "or your key may not have web search permissions."
                    )
                if resp.status_code == 429:
                    raise SearchEngineError(
                        self.name,
                        "Bing rate limit hit. Check your tier's rate limits at "
                        "https://portal.azure.com/"
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
            raise SearchEngineError(self.name, "Connection failed to api.bing.microsoft.com")
        except httpx.RequestError as e:
            raise SearchEngineError(self.name, f"Request failed: {e}")

        results = self._parse_response(data, num_results)
        return results[:num_results]

    def _parse_response(self, data: dict, num_results: int) -> list[SearchResult]:
        """Parse Bing Web Search API JSON response into SearchResult objects.

        Bing returns results under data["webPages"]["value"].
        Each result has: name, url, snippet, dateLastCrawled.

        Args:
            data: Parsed JSON response from Bing API.
            num_results: Maximum results to return.

        Returns:
            List of SearchResult objects.
        """
        results: list[SearchResult] = []

        web_pages = data.get("webPages", {})
        web_results = web_pages.get("value", [])

        for item in web_results[:num_results]:
            title = item.get("name", "")
            url = item.get("url", "")
            snippet = item.get("snippet", "")

            if not url:
                continue

            results.append(SearchResult(
                title=title or url,
                url=url,
                snippet=snippet,
                source_engine=self.name,
            ))

        return results
